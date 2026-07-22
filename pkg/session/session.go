// Package session manages FGXP session lifecycle and state machine.
package session

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/figox/figox-protocol/pkg/protocol"
)

// State represents the current state of an FGXP session.
type State int32

const (
	StateIdle           State = iota // Initial state
	StateConnecting                  // Transport connecting
	StateAuthenticating              // FGXP auth in progress
	StateActive                      // Fully operational
	StateDraining                    // Graceful shutdown, finishing streams
	StateReconnecting                // Attempting session resumption
	StateFailed                      // Error state
	StateClosed                      // Terminal state
)

// String returns a human-readable state name.
func (s State) String() string {
	switch s {
	case StateIdle:
		return "IDLE"
	case StateConnecting:
		return "CONNECTING"
	case StateAuthenticating:
		return "AUTHENTICATING"
	case StateActive:
		return "ACTIVE"
	case StateDraining:
		return "DRAINING"
	case StateReconnecting:
		return "RECONNECTING"
	case StateFailed:
		return "FAILED"
	case StateClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

// IsTerminal reports whether this state is terminal (CLOSED or FAILED).
func (s State) IsTerminal() bool {
	return s == StateClosed || s == StateFailed
}

// Session represents an active FGXP session between a client and server.
// It manages the session lifecycle, state transitions, and metadata.
type Session struct {
	// Immutable after creation.
	id              string
	createdAt       time.Time

	// Mutable state (atomic for lock-free reads).
	state           atomic.Int32

	// Session metadata (protected by mu).
	mu              sync.RWMutex
	sessionID       []byte // 16-byte session identifier
	resumptionToken []byte // 32-byte resumption token
	tokenExpiry     time.Time
	lastActivity    time.Time
	streamCounter   atomic.Uint32 // next stream ID to allocate

	// Cancellation.
	ctx    context.Context
	cancel context.CancelFunc
}

// NewSession creates a new session in IDLE state.
func NewSession(parentCtx context.Context) *Session {
	ctx, cancel := context.WithCancel(parentCtx)
	s := &Session{
		createdAt: time.Now(),
		ctx:       ctx,
		cancel:    cancel,
	}
	s.state.Store(int32(StateIdle))
	s.mu.Lock()
	s.lastActivity = s.createdAt
	s.mu.Unlock()
	return s
}

// State returns the current session state.
func (s *Session) State() State {
	return State(s.state.Load())
}

// ID returns the session identifier (empty string before authentication).
func (s *Session) ID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return fmt.Sprintf("%x", s.sessionID)
}

// Context returns the session's context, which is cancelled when the
// session transitions to a terminal state.
func (s *Session) Context() context.Context {
	return s.ctx
}

// Transition atomically transitions the session to the next state.
// Returns an error if the transition is not valid.
func (s *Session) Transition(to State) error {
	from := s.State()
	if !isValidTransition(from, to) {
		return fmt.Errorf("fgxp/session: invalid transition %s → %s", from, to)
	}

	if !s.state.CompareAndSwap(int32(from), int32(to)) {
		// State changed between Load and CAS — retry once.
		from = s.State()
		if !isValidTransition(from, to) {
			return fmt.Errorf("fgxp/session: invalid transition %s → %s (race)", from, to)
		}
		if !s.state.CompareAndSwap(int32(from), int32(to)) {
			return fmt.Errorf("fgxp/session: transition race: %s → %s", from, to)
		}
	}

	// Cancel context on terminal states.
	if to.IsTerminal() {
		s.cancel()
	}

	s.touch()
	return nil
}

// SetAuth stores the authentication result in the session.
func (s *Session) SetAuth(sessionID, token []byte, expiry time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessionID = sessionID
	s.resumptionToken = token
	s.tokenExpiry = expiry
}

// ResumptionToken returns the current resumption token and its expiry.
func (s *Session) ResumptionToken() ([]byte, time.Time) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.resumptionToken, s.tokenExpiry
}

// SessionID returns the raw session ID bytes.
func (s *Session) SessionID() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

// NextClientStreamID allocates the next client-initiated stream ID.
func (s *Session) NextClientStreamID() uint32 {
	return s.streamCounter.Add(1)
}

// NextServerStreamID allocates the next server-initiated stream ID.
func (s *Session) NextServerStreamID() uint32 {
	return s.streamCounter.Add(1) | protocol.StreamDirectionBit
}

// touch updates the last activity timestamp.
func (s *Session) touch() {
	s.mu.Lock()
	s.lastActivity = time.Now()
	s.mu.Unlock()
}

// LastActivity returns the time of last activity on this session.
func (s *Session) LastActivity() time.Time {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.lastActivity
}

// IsActive reports whether the session is in ACTIVE state.
func (s *Session) IsActive() bool {
	return s.State() == StateActive
}

// Close transitions the session to CLOSED state.
func (s *Session) Close() error {
	state := s.State()
	if state.IsTerminal() {
		return nil // Already closed.
	}
	return s.Transition(StateClosed)
}

// isValidTransition checks if a state transition is allowed.
func isValidTransition(from, to State) bool {
	switch from {
	case StateIdle:
		return to == StateConnecting
	case StateConnecting:
		return to == StateAuthenticating || to == StateFailed
	case StateAuthenticating:
		return to == StateActive || to == StateFailed
	case StateActive:
		return to == StateDraining || to == StateReconnecting || to == StateFailed || to == StateClosed
	case StateDraining:
		return to == StateClosed
	case StateReconnecting:
		return to == StateActive || to == StateFailed
	case StateFailed:
		return to == StateConnecting || to == StateClosed
	case StateClosed:
		return false // Terminal state — no transitions out.
	default:
		return false
	}
}

// StreamState represents the state of a multiplexed stream.
type StreamState int32

const (
	StreamIdle          StreamState = iota
	StreamOpen
	StreamHalfCloseLocal
	StreamHalfCloseRemote
	StreamClosed
)

// String returns a human-readable stream state name.
func (s StreamState) String() string {
	switch s {
	case StreamIdle:
		return "IDLE"
	case StreamOpen:
		return "OPEN"
	case StreamHalfCloseLocal:
		return "HALF_CLOSE_LOCAL"
	case StreamHalfCloseRemote:
		return "HALF_CLOSE_REMOTE"
	case StreamClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}
