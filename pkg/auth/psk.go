package auth

import (
	"context"
	"fmt"
	"sync"
	"time"

	fgxpcrypto "github.com/figox/figox-protocol/internal/crypto"
	"github.com/figox/figox-protocol/pkg/protocol"
)

// PSKAuthenticator implements server-side PSK authentication.
type PSKAuthenticator struct {
	store PSKStore

	// Anti-replay: tracks recently seen (clientNonce, timestamp) pairs.
	mu       sync.Mutex
	seenKeys map[string]time.Time
}

// NewPSKAuthenticator creates a server-side PSK authenticator.
func NewPSKAuthenticator(store PSKStore) *PSKAuthenticator {
	a := &PSKAuthenticator{
		store:    store,
		seenKeys: make(map[string]time.Time),
	}
	return a
}

// Authenticate performs the server-side PSK authentication exchange.
//
// Protocol:
//  1. Read AUTH(INIT) from client → extract KeyID + ClientNonce
//  2. Lookup PSK by KeyID
//  3. Send AUTH(CHALLENGE) with ServerNonce + Timestamp
//  4. Read AUTH(RESPONSE) from client → extract HMAC proof
//  5. Verify HMAC = HMAC-SHA256(PSK, clientNonce || serverNonce || timestamp)
//  6. Send AUTH(SUCCESS) with SessionID + ResumptionToken, or AUTH(FAILURE)
func (a *PSKAuthenticator) Authenticate(ctx context.Context, rw FrameReadWriter) (Result, error) {
	// Phase 1: Read INIT
	initFrame, err := rw.ReadFrame()
	if err != nil {
		return Result{}, fmt.Errorf("fgxp/auth: read init: %w", err)
	}
	if err := validateAuthFrame(initFrame, protocol.AuthPhaseInit); err != nil {
		return Result{}, err
	}

	identity, err := parseInitPayload(initFrame.Payload)
	if err != nil {
		return a.sendFailure(rw, protocol.ErrAuthFailed, "malformed init")
	}

	// Lookup PSK
	psk, ok := a.store.Lookup(identity.KeyID)
	if !ok {
		return a.sendFailure(rw, protocol.ErrAuthFailed, "unknown key")
	}

	// Phase 2: Send CHALLENGE
	serverNonce, err := fgxpcrypto.GenerateNonce(protocol.NonceLength)
	if err != nil {
		return Result{}, fmt.Errorf("fgxp/auth: generate nonce: %w", err)
	}
	timestamp := fgxpcrypto.TimestampBytes()

	challengePayload := buildChallengePayload(serverNonce, timestamp)
	challengeFrame := &protocol.Frame{
		Version:  protocol.CurrentVersion,
		Type:     protocol.FrameAuth,
		StreamID: protocol.ControlStreamID,
		Payload:  challengePayload,
	}
	if err := rw.WriteFrame(challengeFrame); err != nil {
		return Result{}, fmt.Errorf("fgxp/auth: write challenge: %w", err)
	}

	// Phase 3: Read RESPONSE
	respFrame, err := rw.ReadFrame()
	if err != nil {
		return Result{}, fmt.Errorf("fgxp/auth: read response: %w", err)
	}
	if err := validateAuthFrame(respFrame, protocol.AuthPhaseResponse); err != nil {
		return Result{}, err
	}

	resp, err := parseResponsePayload(respFrame.Payload)
	if err != nil {
		return a.sendFailure(rw, protocol.ErrAuthFailed, "malformed response")
	}

	// Anti-replay check
	if !a.checkAndRecordNonce(identity.ClientNonce, timestamp) {
		return a.sendFailure(rw, protocol.ErrAuthFailed, "replay detected")
	}

	// Verify HMAC proof
	hmacData := concat(identity.ClientNonce, serverNonce, timestamp)
	if !fgxpcrypto.VerifyHMAC(psk, hmacData, resp.Proof) {
		return a.sendFailure(rw, protocol.ErrAuthFailed, "invalid proof")
	}

	// Phase 4: Send SUCCESS
	sessionID, err := fgxpcrypto.GenerateSessionID()
	if err != nil {
		return Result{}, fmt.Errorf("fgxp/auth: generate session id: %w", err)
	}
	token, err := fgxpcrypto.GenerateResumptionToken()
	if err != nil {
		return Result{}, fmt.Errorf("fgxp/auth: generate token: %w", err)
	}
	expiry := time.Now().Add(protocol.DefaultSessionTimeout)

	successPayload := buildSuccessPayload(sessionID, token, expiry)
	successFrame := &protocol.Frame{
		Version:  protocol.CurrentVersion,
		Type:     protocol.FrameAuth,
		StreamID: protocol.ControlStreamID,
		Payload:  successPayload,
	}
	if err := rw.WriteFrame(successFrame); err != nil {
		return Result{}, fmt.Errorf("fgxp/auth: write success: %w", err)
	}

	return Result{
		Success:         true,
		SessionID:       sessionID,
		ResumptionToken: token,
		TokenExpiry:     expiry,
	}, nil
}

// sendFailure sends an AUTH(FAILURE) frame and returns a failed Result.
func (a *PSKAuthenticator) sendFailure(rw FrameReadWriter, code protocol.ErrorCode, msg string) (Result, error) {
	failPayload := buildFailurePayload(code)
	failFrame := &protocol.Frame{
		Version:  protocol.CurrentVersion,
		Type:     protocol.FrameAuth,
		StreamID: protocol.ControlStreamID,
		Payload:  failPayload,
	}
	// Best effort: ignore write error since we're already failing.
	_ = rw.WriteFrame(failFrame)

	return Result{
		Success:      false,
		ErrorCode:    code,
		ErrorMessage: msg,
	}, nil
}

// checkAndRecordNonce checks for replay and records the nonce.
// Returns false if replay is detected.
func (a *PSKAuthenticator) checkAndRecordNonce(clientNonce, timestamp []byte) bool {
	ts := fgxpcrypto.ParseTimestamp(timestamp)
	now := time.Now()

	// Reject if timestamp is too old or too far in the future.
	if now.Sub(ts) > protocol.AntiReplayWindow {
		return false
	}
	if ts.Sub(now) > protocol.MaxClockSkew {
		return false
	}

	key := string(clientNonce) + string(timestamp)

	a.mu.Lock()
	defer a.mu.Unlock()

	if _, seen := a.seenKeys[key]; seen {
		return false // replay
	}
	a.seenKeys[key] = now

	// Cleanup old entries (best effort, non-blocking).
	for k, t := range a.seenKeys {
		if now.Sub(t) > protocol.AntiReplayWindow {
			delete(a.seenKeys, k)
		}
	}

	return true
}

// validateAuthFrame checks that a frame is a valid AUTH frame with the expected phase.
func validateAuthFrame(f *protocol.Frame, expectedPhase protocol.AuthPhase) error {
	if f.Type != protocol.FrameAuth {
		return protocol.NewProtocolErrorf(protocol.ErrProtocol,
			"expected AUTH frame, got %s", f.Type)
	}
	if f.StreamID != protocol.ControlStreamID {
		return protocol.NewProtocolError(protocol.ErrInvalidStreamID,
			"AUTH must be on control stream")
	}
	if len(f.Payload) < 2 {
		return protocol.NewProtocolError(protocol.ErrFrameFormat,
			"AUTH payload too short")
	}
	if protocol.AuthPhase(f.Payload[1]) != expectedPhase {
		return protocol.NewProtocolErrorf(protocol.ErrProtocol,
			"expected auth phase %d, got %d", expectedPhase, f.Payload[1])
	}
	return nil
}

// Payload builders and parsers.

func parseInitPayload(payload []byte) (*Identity, error) {
	// Layout: method(1) + phase(1) + keyID(8) + clientNonce(32) = 42 bytes
	if len(payload) < 42 {
		return nil, fmt.Errorf("init payload too short: %d", len(payload))
	}
	return &Identity{
		KeyID:       payload[2:10],
		ClientNonce: payload[10:42],
	}, nil
}

func buildChallengePayload(serverNonce, timestamp []byte) []byte {
	// Layout: method(1) + phase(1) + serverNonce(32) + timestamp(8) = 42 bytes
	payload := make([]byte, 42)
	payload[0] = byte(protocol.AuthMethodPSK)
	payload[1] = byte(protocol.AuthPhaseChallenge)
	copy(payload[2:34], serverNonce)
	copy(payload[34:42], timestamp)
	return payload
}

func parseResponsePayload(payload []byte) (*Response, error) {
	// Layout: method(1) + phase(1) + proof(32) = 34 bytes
	if len(payload) < 34 {
		return nil, fmt.Errorf("response payload too short: %d", len(payload))
	}
	return &Response{
		Proof: payload[2:34],
	}, nil
}

func buildSuccessPayload(sessionID, token []byte, expiry time.Time) []byte {
	// Layout: method(1) + phase(1) + sessionID(16) + token(32) + expiry(8) = 58 bytes
	payload := make([]byte, 58)
	payload[0] = byte(protocol.AuthMethodPSK)
	payload[1] = byte(protocol.AuthPhaseSuccess)
	copy(payload[2:18], sessionID)
	copy(payload[18:50], token)
	ts := make([]byte, 8)
	tsVal := uint64(expiry.UnixMilli())
	ts[0] = byte(tsVal >> 56)
	ts[1] = byte(tsVal >> 48)
	ts[2] = byte(tsVal >> 40)
	ts[3] = byte(tsVal >> 32)
	ts[4] = byte(tsVal >> 24)
	ts[5] = byte(tsVal >> 16)
	ts[6] = byte(tsVal >> 8)
	ts[7] = byte(tsVal)
	copy(payload[50:58], ts)
	return payload
}

func buildFailurePayload(code protocol.ErrorCode) []byte {
	payload := make([]byte, 6)
	payload[0] = byte(protocol.AuthMethodPSK)
	payload[1] = byte(protocol.AuthPhaseFailure)
	payload[2] = byte(code >> 24)
	payload[3] = byte(code >> 16)
	payload[4] = byte(code >> 8)
	payload[5] = byte(code)
	return payload
}

// concat joins multiple byte slices into one.
func concat(parts ...[]byte) []byte {
	total := 0
	for _, p := range parts {
		total += len(p)
	}
	result := make([]byte, 0, total)
	for _, p := range parts {
		result = append(result, p...)
	}
	return result
}

// PSKClientAuthenticator implements client-side PSK authentication.
type PSKClientAuthenticator struct {
	psk []byte
}

// NewPSKClientAuthenticator creates a client-side PSK authenticator.
func NewPSKClientAuthenticator(psk []byte) *PSKClientAuthenticator {
	return &PSKClientAuthenticator{psk: psk}
}

// Authenticate performs the client-side PSK authentication exchange.
func (a *PSKClientAuthenticator) Authenticate(ctx context.Context, rw FrameReadWriter) (Result, error) {
	keyID := ComputeKeyID(a.psk)
	clientNonce, err := fgxpcrypto.GenerateNonce(protocol.NonceLength)
	if err != nil {
		return Result{}, fmt.Errorf("fgxp/auth: generate nonce: %w", err)
	}

	// Phase 1: Send INIT
	initPayload := make([]byte, 42)
	initPayload[0] = byte(protocol.AuthMethodPSK)
	initPayload[1] = byte(protocol.AuthPhaseInit)
	copy(initPayload[2:10], keyID)
	copy(initPayload[10:42], clientNonce)

	initFrame := &protocol.Frame{
		Version:  protocol.CurrentVersion,
		Type:     protocol.FrameAuth,
		StreamID: protocol.ControlStreamID,
		Payload:  initPayload,
	}
	if err := rw.WriteFrame(initFrame); err != nil {
		return Result{}, fmt.Errorf("fgxp/auth: write init: %w", err)
	}

	// Phase 2: Read CHALLENGE
	challengeFrame, err := rw.ReadFrame()
	if err != nil {
		return Result{}, fmt.Errorf("fgxp/auth: read challenge: %w", err)
	}

	// Check if server sent FAILURE instead of CHALLENGE
	if len(challengeFrame.Payload) >= 2 &&
		protocol.AuthPhase(challengeFrame.Payload[1]) == protocol.AuthPhaseFailure {
		return Result{
			Success:      false,
			ErrorCode:    protocol.ErrAuthFailed,
			ErrorMessage: "server rejected auth",
		}, nil
	}

	if err := validateAuthFrame(challengeFrame, protocol.AuthPhaseChallenge); err != nil {
		return Result{}, err
	}

	if len(challengeFrame.Payload) < 42 {
		return Result{}, protocol.NewProtocolError(protocol.ErrFrameFormat,
			"challenge payload too short")
	}

	serverNonce := challengeFrame.Payload[2:34]
	timestamp := challengeFrame.Payload[34:42]

	// Phase 3: Compute and send RESPONSE
	hmacData := concat(clientNonce, serverNonce, timestamp)
	proof := fgxpcrypto.ComputeHMAC(a.psk, hmacData)

	respPayload := make([]byte, 34)
	respPayload[0] = byte(protocol.AuthMethodPSK)
	respPayload[1] = byte(protocol.AuthPhaseResponse)
	copy(respPayload[2:34], proof)

	respFrame := &protocol.Frame{
		Version:  protocol.CurrentVersion,
		Type:     protocol.FrameAuth,
		StreamID: protocol.ControlStreamID,
		Payload:  respPayload,
	}
	if err := rw.WriteFrame(respFrame); err != nil {
		return Result{}, fmt.Errorf("fgxp/auth: write response: %w", err)
	}

	// Phase 4: Read SUCCESS or FAILURE
	resultFrame, err := rw.ReadFrame()
	if err != nil {
		return Result{}, fmt.Errorf("fgxp/auth: read result: %w", err)
	}

	if len(resultFrame.Payload) < 2 {
		return Result{}, protocol.NewProtocolError(protocol.ErrFrameFormat,
			"result payload too short")
	}

	phase := protocol.AuthPhase(resultFrame.Payload[1])
	if phase == protocol.AuthPhaseFailure {
		return Result{
			Success:      false,
			ErrorCode:    protocol.ErrAuthFailed,
			ErrorMessage: "authentication failed",
		}, nil
	}

	if phase != protocol.AuthPhaseSuccess {
		return Result{}, protocol.NewProtocolErrorf(protocol.ErrProtocol,
			"unexpected auth phase: %d", phase)
	}

	// Parse success payload
	if len(resultFrame.Payload) < 58 {
		return Result{}, protocol.NewProtocolError(protocol.ErrFrameFormat,
			"success payload too short")
	}

	sessionID := make([]byte, protocol.SessionIDLength)
	copy(sessionID, resultFrame.Payload[2:18])

	token := make([]byte, protocol.ResumptionTokenLength)
	copy(token, resultFrame.Payload[18:50])

	expiryTS := fgxpcrypto.ParseTimestamp(resultFrame.Payload[50:58])

	return Result{
		Success:         true,
		SessionID:       sessionID,
		ResumptionToken: token,
		TokenExpiry:     expiryTS,
	}, nil
}

// BuildInitFrame creates an AUTH(INIT) frame for the given PSK.
// Exported for testing purposes.
func BuildInitFrame(psk []byte) (*protocol.Frame, []byte, error) {
	keyID := ComputeKeyID(psk)
	clientNonce, err := fgxpcrypto.GenerateNonce(protocol.NonceLength)
	if err != nil {
		return nil, nil, err
	}

	payload := make([]byte, 42)
	payload[0] = byte(protocol.AuthMethodPSK)
	payload[1] = byte(protocol.AuthPhaseInit)
	copy(payload[2:10], keyID)
	copy(payload[10:42], clientNonce)

	return &protocol.Frame{
		Version:  protocol.CurrentVersion,
		Type:     protocol.FrameAuth,
		StreamID: protocol.ControlStreamID,
		Payload:  payload,
	}, clientNonce, nil
}

// IsFirstByteFGXP checks if the first byte of a connection looks like
// an FGXP AUTH frame. This is used by the camouflage server to distinguish
// FGXP clients from HTTP probers.
//
// FGXP first byte: high nibble = version (0x1), low nibble = AUTH type (0x9)
// → first byte = 0x19
func IsFirstByteFGXP(b byte) bool {
	version := Version(b >> 4)
	frameType := FrameType(b & 0x0F)
	return version == protocol.Version1 && frameType == protocol.FrameAuth
}

// Version and FrameType aliases for the first-byte check.
type Version = protocol.Version
type FrameType = protocol.FrameType
