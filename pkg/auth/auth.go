// Package auth implements FGXP authentication mechanisms.
// Currently supports PSK (Pre-Shared Key) with HMAC-SHA256 challenge-response.
package auth

import (
	"context"
	"crypto/sha256"
	"time"

	"github.com/figox/figox-protocol/pkg/protocol"
)

// Result represents the outcome of an authentication attempt.
type Result struct {
	Success         bool
	SessionID       []byte // 16 bytes, set on success
	ResumptionToken []byte // 32 bytes, set on success
	TokenExpiry     time.Time
	ErrorCode       protocol.ErrorCode
	ErrorMessage    string
}

// Identity carries information about the authenticating client.
type Identity struct {
	KeyID       []byte // 8-byte key identifier
	ClientNonce []byte // 32-byte random nonce
}

// Challenge carries the server's challenge to the client.
type Challenge struct {
	ServerNonce []byte // 32-byte random nonce
	Timestamp   []byte // 8-byte unix millisecond timestamp
}

// Response carries the client's proof of PSK possession.
type Response struct {
	Proof []byte // 32-byte HMAC-SHA256
}

// Authenticator defines the server-side authentication interface.
type Authenticator interface {
	// Authenticate performs the full server-side authentication exchange.
	Authenticate(ctx context.Context, rw FrameReadWriter) (Result, error)
}

// ClientAuthenticator defines the client-side authentication interface.
type ClientAuthenticator interface {
	// Authenticate performs client-side authentication.
	Authenticate(ctx context.Context, rw FrameReadWriter) (Result, error)
}

// FrameReadWriter reads and writes FGXP frames. This abstracts the
// transport layer for authentication purposes.
type FrameReadWriter interface {
	ReadFrame() (*protocol.Frame, error)
	WriteFrame(f *protocol.Frame) error
}

// PSKStore manages pre-shared keys. Implementations must be safe for
// concurrent access.
type PSKStore interface {
	// Lookup returns the PSK for a given key ID.
	Lookup(keyID []byte) (psk []byte, ok bool)

	// List returns all active key IDs.
	List() [][]byte
}

// MemoryPSKStore is a simple in-memory PSK store for testing and
// single-key deployments.
type MemoryPSKStore struct {
	keys map[string][]byte // string(keyID) → PSK
}

// NewMemoryPSKStore creates a new in-memory PSK store.
func NewMemoryPSKStore() *MemoryPSKStore {
	return &MemoryPSKStore{keys: make(map[string][]byte)}
}

// AddKey adds a PSK to the store. The key ID is computed from SHA256(PSK)[0:8].
func (s *MemoryPSKStore) AddKey(psk []byte) {
	keyID := ComputeKeyID(psk)
	s.keys[string(keyID)] = append([]byte(nil), psk...)
}

// Lookup implements PSKStore.
func (s *MemoryPSKStore) Lookup(keyID []byte) ([]byte, bool) {
	psk, ok := s.keys[string(keyID)]
	return psk, ok
}

// List implements PSKStore.
func (s *MemoryPSKStore) List() [][]byte {
	ids := make([][]byte, 0, len(s.keys))
	for id := range s.keys {
		ids = append(ids, []byte(id))
	}
	return ids
}

// ComputeKeyID returns SHA256(psk)[0:8] as the key identifier.
func ComputeKeyID(psk []byte) []byte {
	hash := sha256.Sum256(psk)
	id := make([]byte, protocol.PSKKeyIDLength)
	copy(id, hash[:protocol.PSKKeyIDLength])
	return id
}
