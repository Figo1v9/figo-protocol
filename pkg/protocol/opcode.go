package protocol

// FrameType represents the 4-bit type field in the frame header.
type FrameType uint8

const (
	FrameData         FrameType = 0x0 // User data
	FrameControl      FrameType = 0x1 // Control metadata (key-value)
	FrameWindowUpdate FrameType = 0x2 // Flow control credit
	FramePing         FrameType = 0x3 // Keepalive / latency probe
	FramePong         FrameType = 0x4 // Ping response
	FrameStreamOpen   FrameType = 0x5 // Open a new stream
	FrameStreamClose  FrameType = 0x6 // Graceful stream close
	FrameStreamReset  FrameType = 0x7 // Abrupt stream termination
	FrameGoAway       FrameType = 0x8 // Session shutdown
	FrameAuth         FrameType = 0x9 // Authentication exchange
	FrameSessionResume FrameType = 0xA // Resume prior session
	FrameConfig       FrameType = 0xB // Configuration exchange
	// 0xC-0xE are reserved for future use.
	FrameExtension FrameType = 0xF // Plugin-defined frames
)

// IsValid reports whether ft is a defined frame type.
func (ft FrameType) IsValid() bool {
	return ft <= FrameConfig || ft == FrameExtension
}

// IsReserved reports whether ft is in the reserved range.
func (ft FrameType) IsReserved() bool {
	return ft >= 0xC && ft <= 0xE
}

// String returns a human-readable name for the frame type.
func (ft FrameType) String() string {
	switch ft {
	case FrameData:
		return "DATA"
	case FrameControl:
		return "CONTROL"
	case FrameWindowUpdate:
		return "WINDOW_UPDATE"
	case FramePing:
		return "PING"
	case FramePong:
		return "PONG"
	case FrameStreamOpen:
		return "STREAM_OPEN"
	case FrameStreamClose:
		return "STREAM_CLOSE"
	case FrameStreamReset:
		return "STREAM_RESET"
	case FrameGoAway:
		return "GOAWAY"
	case FrameAuth:
		return "AUTH"
	case FrameSessionResume:
		return "SESSION_RESUME"
	case FrameConfig:
		return "CONFIG"
	case FrameExtension:
		return "EXTENSION"
	default:
		return "RESERVED"
	}
}

// Flag represents individual bits in the 8-bit Flags field.
type Flag uint8

const (
	FlagFIN        Flag = 0x01 // Last frame for this stream
	FlagCompressed Flag = 0x02 // Payload is compressed
	FlagPriority   Flag = 0x04 // Frame carries priority data
	FlagACK        Flag = 0x08 // Acknowledgment
	FlagUrgent     Flag = 0x10 // Bypass flow control
	FlagEncrypted  Flag = 0x20 // Additional encryption layer
	// Bits 6-7 (0x40, 0x80) are reserved and must be zero.
)

// Flags is a bitfield combining multiple Flag values.
type Flags uint8

// Has reports whether f contains the given flag.
func (f Flags) Has(flag Flag) bool {
	return f&Flags(flag) != 0
}

// Set returns f with the given flag set.
func (f Flags) Set(flag Flag) Flags {
	return f | Flags(flag)
}

// Clear returns f with the given flag cleared.
func (f Flags) Clear(flag Flag) Flags {
	return f &^ Flags(flag)
}

// reservedMask covers bits 6 and 7 which must be zero.
const reservedFlagsMask Flags = 0xC0

// IsValid reports whether f has no reserved bits set.
func (f Flags) IsValid() bool {
	return f&reservedFlagsMask == 0
}

// AuthMethod identifies the authentication mechanism.
type AuthMethod uint8

const (
	AuthMethodPSK         AuthMethod = 0x01 // Pre-Shared Key
	AuthMethodHMAC        AuthMethod = 0x02 // HMAC-SHA256 Challenge-Response
	AuthMethodCertificate AuthMethod = 0x03 // Certificate-based (future)
)

// AuthPhase identifies the current phase of the authentication exchange.
type AuthPhase uint8

const (
	AuthPhaseInit      AuthPhase = 0x01 // Client → Server: initiate auth
	AuthPhaseChallenge AuthPhase = 0x02 // Server → Client: send challenge
	AuthPhaseResponse  AuthPhase = 0x03 // Client → Server: send proof
	AuthPhaseSuccess   AuthPhase = 0x04 // Server → Client: auth succeeded
	AuthPhaseFailure   AuthPhase = 0x05 // Server → Client: auth failed
)

// StreamType identifies the kind of stream being opened.
type StreamType uint8

const (
	StreamBidirectional StreamType = 0x01 // Both sides read/write
	StreamUnidirectional StreamType = 0x02 // Opener writes, receiver reads
	StreamTunnel         StreamType = 0x03 // TCP proxy target
)

// SettingID identifies a configuration setting in CONFIG frames.
type SettingID uint16

const (
	SettingMaxConcurrentStreams SettingID = 0x0001
	SettingInitialWindowSize   SettingID = 0x0002
	SettingMaxFramePayloadSize SettingID = 0x0003
	SettingCompressionAlgorithm SettingID = 0x0004
	SettingKeepaliveIntervalMS SettingID = 0x0005
	SettingSessionTimeoutMS    SettingID = 0x0006
	SettingStealthPaddingMode  SettingID = 0x0007
	SettingMaxHeaderSize       SettingID = 0x0008
	// Stealth timing negotiation (Stage 2).
	SettingStealthTimingEnabled SettingID = 0x0009
	SettingStealthTimingJitterMS SettingID = 0x000A
)

// CompressionAlgorithm identifies the compression method.
type CompressionAlgorithm uint32

const (
	CompressionNone CompressionAlgorithm = 0
	CompressionLZ4  CompressionAlgorithm = 1
	CompressionZstd CompressionAlgorithm = 2
)

// PaddingMode identifies the stealth padding strategy.
type PaddingMode uint32

const (
	PaddingNone       PaddingMode = 0
	PaddingRandom     PaddingMode = 1
	PaddingNormalized PaddingMode = 2
)
