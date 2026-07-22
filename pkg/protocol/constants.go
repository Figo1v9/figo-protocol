package protocol

import "time"

// Header and frame size constants.
const (
	// HeaderSize is the fixed size of every FGXP frame header in bytes.
	HeaderSize = 16

	// MaxPayloadLength is the maximum value of the 16-bit Payload Length field.
	MaxPayloadLength = (1 << 16) - 1 // 65535

	// MaxPaddingLength is the maximum value of the 8-bit Pad Length field.
	MaxPaddingLength = (1 << 8) - 1 // 255

	// MaxFrameSize is the maximum total size of a frame (header + payload).
	MaxFrameSize = HeaderSize + MaxPayloadLength // 65551
)

// Stream constants.
const (
	// ControlStreamID is the reserved stream for session-level control frames.
	ControlStreamID uint32 = 0

	// MaxStreamID is the largest valid stream ID (excluding direction bit).
	MaxStreamID uint32 = (1 << 31) - 1 // 2,147,483,647

	// StreamDirectionBit is the MSB that indicates server-initiated streams.
	StreamDirectionBit uint32 = 1 << 31

	// FirstClientStreamID is the ID of the first client-initiated stream.
	FirstClientStreamID uint32 = 1

	// FirstServerStreamID is the ID of the first server-initiated stream.
	FirstServerStreamID = StreamDirectionBit | 1
)

// Flow control defaults.
const (
	// DefaultConnectionWindowSize is the default connection-level flow control
	// window in bytes (1 MB).
	DefaultConnectionWindowSize = 1 << 20 // 1,048,576

	// DefaultStreamWindowSize is the default per-stream flow control window
	// in bytes (256 KB).
	DefaultStreamWindowSize = 1 << 18 // 262,144

	// MaxWindowSize is the maximum flow control window (2 GB - 1).
	MaxWindowSize = (1 << 31) - 1 // 2,147,483,647
)

// Session and connection defaults.
const (
	// DefaultMaxConcurrentStreams is the default maximum number of concurrent
	// streams per session.
	DefaultMaxConcurrentStreams = 100

	// DefaultMaxFramePayloadSize is the default maximum frame payload size
	// that the receiver is willing to accept.
	DefaultMaxFramePayloadSize = 16384 // 16 KB, matches TLS record size

	// DefaultKeepaliveInterval is the default interval between PING frames.
	DefaultKeepaliveInterval = 30 * time.Second

	// DefaultSessionTimeout is the default idle timeout before a session is
	// closed automatically.
	DefaultSessionTimeout = 5 * time.Minute

	// DefaultHandshakeTimeout is the maximum time allowed for the complete
	// handshake (TLS + FGXP auth).
	DefaultHandshakeTimeout = 10 * time.Second

	// DefaultDrainTimeout is the maximum time to wait for in-flight streams
	// to complete during graceful shutdown.
	DefaultDrainTimeout = 30 * time.Second
)

// Authentication constants.
const (
	// PSKKeyIDLength is the length of the key ID derived from SHA256(PSK).
	PSKKeyIDLength = 8

	// NonceLength is the length of client and server nonces.
	NonceLength = 32

	// HMACProofLength is the length of the HMAC-SHA256 proof.
	HMACProofLength = 32

	// SessionIDLength is the length of a session identifier.
	SessionIDLength = 16

	// ResumptionTokenLength is the length of a session resumption token.
	ResumptionTokenLength = 32

	// TimestampLength is the length of a unix millisecond timestamp.
	TimestampLength = 8

	// AntiReplayWindow is the duration for which nonces are remembered to
	// prevent replay attacks.
	AntiReplayWindow = 5 * time.Minute

	// MaxClockSkew is the maximum acceptable clock difference between
	// client and server.
	MaxClockSkew = 30 * time.Second
)

// Stealth defaults.
const (
	// DefaultMinPadding is the default minimum padding added to frames.
	DefaultMinPadding = 0

	// DefaultMaxPadding is the default maximum padding added to frames.
	DefaultMaxPadding = 255

	// DefaultTimingJitter is the default maximum timing jitter in milliseconds.
	DefaultTimingJitterMS = 50
)

// Limits.
const (
	// DefaultMaxConnections is the default server-wide connection limit.
	DefaultMaxConnections = 10000

	// DefaultMaxHeaderSize is the maximum size for CONTROL frame metadata.
	DefaultMaxHeaderSize = 8192
)
