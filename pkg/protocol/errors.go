package protocol

import "fmt"

// ErrorCode is a 32-bit error code transmitted in GOAWAY, STREAM_RESET,
// and AUTH frames.
type ErrorCode uint32

// Protocol errors (0x0000–0x00FF).
const (
	ErrNoError          ErrorCode = 0x00000000
	ErrProtocol         ErrorCode = 0x00000001
	ErrFrameSize        ErrorCode = 0x00000002
	ErrFrameFormat      ErrorCode = 0x00000003
	ErrInvalidVersion   ErrorCode = 0x00000004
	ErrInvalidFrameType ErrorCode = 0x00000005
	ErrInvalidStreamID  ErrorCode = 0x00000006
	ErrInvalidSequence  ErrorCode = 0x00000007
	ErrCompression      ErrorCode = 0x00000008
)

// Authentication errors (0x0100–0x01FF).
const (
	ErrAuthRequired         ErrorCode = 0x00000100
	ErrAuthFailed           ErrorCode = 0x00000101
	ErrAuthExpired          ErrorCode = 0x00000102
	ErrAuthMethodUnsupported ErrorCode = 0x00000103
)

// Stream errors (0x0200–0x02FF).
const (
	ErrStreamClosed       ErrorCode = 0x00000200
	ErrStreamRefused      ErrorCode = 0x00000201
	ErrStreamLimitExceeded ErrorCode = 0x00000202
	ErrStreamCancelled    ErrorCode = 0x00000203
)

// Flow control errors (0x0300–0x03FF).
const (
	ErrFlowControl    ErrorCode = 0x00000300
	ErrWindowUpdate   ErrorCode = 0x00000301
)

// Transport errors (0x0400–0x04FF).
const (
	ErrTransport      ErrorCode = 0x00000400
	ErrTLS            ErrorCode = 0x00000401
	ErrQUIC           ErrorCode = 0x00000402
	ErrConnectTimeout ErrorCode = 0x00000403
)

// Internal errors (0x0500–0x05FF).
const (
	ErrInternal          ErrorCode = 0x00000500
	ErrResourceExhausted ErrorCode = 0x00000501
)

// Plugin errors (0x0600–0x06FF).
const (
	ErrPlugin ErrorCode = 0x00000600
)

// IsApplicationDefined reports whether the error code is in the
// application-defined range (0x80000000–0xFFFFFFFF).
func (e ErrorCode) IsApplicationDefined() bool {
	return e >= 0x80000000
}

// String returns a human-readable name for the error code.
func (e ErrorCode) String() string {
	switch e {
	case ErrNoError:
		return "NO_ERROR"
	case ErrProtocol:
		return "PROTOCOL_ERROR"
	case ErrFrameSize:
		return "FRAME_SIZE_ERROR"
	case ErrFrameFormat:
		return "FRAME_FORMAT_ERROR"
	case ErrInvalidVersion:
		return "INVALID_VERSION"
	case ErrInvalidFrameType:
		return "INVALID_FRAME_TYPE"
	case ErrInvalidStreamID:
		return "INVALID_STREAM_ID"
	case ErrInvalidSequence:
		return "INVALID_SEQUENCE"
	case ErrCompression:
		return "COMPRESSION_ERROR"
	case ErrAuthRequired:
		return "AUTH_REQUIRED"
	case ErrAuthFailed:
		return "AUTH_FAILED"
	case ErrAuthExpired:
		return "AUTH_EXPIRED"
	case ErrAuthMethodUnsupported:
		return "AUTH_METHOD_UNSUPPORTED"
	case ErrStreamClosed:
		return "STREAM_CLOSED"
	case ErrStreamRefused:
		return "STREAM_REFUSED"
	case ErrStreamLimitExceeded:
		return "STREAM_LIMIT_EXCEEDED"
	case ErrStreamCancelled:
		return "STREAM_CANCELLED"
	case ErrFlowControl:
		return "FLOW_CONTROL_ERROR"
	case ErrWindowUpdate:
		return "WINDOW_UPDATE_ERROR"
	case ErrTransport:
		return "TRANSPORT_ERROR"
	case ErrTLS:
		return "TLS_ERROR"
	case ErrQUIC:
		return "QUIC_ERROR"
	case ErrConnectTimeout:
		return "CONNECT_TIMEOUT"
	case ErrInternal:
		return "INTERNAL_ERROR"
	case ErrResourceExhausted:
		return "RESOURCE_EXHAUSTED"
	case ErrPlugin:
		return "PLUGIN_ERROR"
	default:
		if e.IsApplicationDefined() {
			return fmt.Sprintf("APP_ERROR(0x%08X)", uint32(e))
		}
		return fmt.Sprintf("UNKNOWN_ERROR(0x%08X)", uint32(e))
	}
}

// ProtocolError is an error type that carries an FGXP error code along with
// a human-readable message. It satisfies the error interface.
type ProtocolError struct {
	Code    ErrorCode
	Message string
}

// Error implements the error interface.
func (e *ProtocolError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("fgxp: %s: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("fgxp: %s", e.Code)
}

// NewProtocolError creates a ProtocolError with the given code and message.
func NewProtocolError(code ErrorCode, msg string) *ProtocolError {
	return &ProtocolError{Code: code, Message: msg}
}

// NewProtocolErrorf creates a ProtocolError with a formatted message.
func NewProtocolErrorf(code ErrorCode, format string, args ...any) *ProtocolError {
	return &ProtocolError{Code: code, Message: fmt.Sprintf(format, args...)}
}
