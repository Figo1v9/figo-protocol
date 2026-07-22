// Package protocol defines the FGXP wire format, constants, frame types,
// and error codes. This is the foundation layer that all other packages depend on.
package protocol

// Version represents the FGXP protocol version as a 4-bit value (0x0–0xF).
type Version uint8

const (
	// VersionInvalid is reserved and must never appear on the wire.
	VersionInvalid Version = 0x0

	// Version1 is the first version of the FGXP protocol (this specification).
	Version1 Version = 0x1

	// VersionNegotiation is a special version used during version negotiation.
	// A frame with this version carries a list of supported versions.
	VersionNegotiation Version = 0xF
)

// CurrentVersion is the version used by this implementation.
const CurrentVersion = Version1

// MaxVersion is the highest valid protocol version (excluding negotiation).
const MaxVersion = Version(0xE)

// IsValid reports whether v is a usable protocol version.
// VersionNegotiation is valid for negotiation frames but is not a usable
// protocol version for data exchange.
func (v Version) IsValid() bool {
	return v >= Version1 && v <= MaxVersion
}

// String returns a human-readable representation of the version.
func (v Version) String() string {
	switch v {
	case VersionInvalid:
		return "invalid"
	case Version1:
		return "FGXPv1"
	case VersionNegotiation:
		return "negotiation"
	default:
		return "unknown"
	}
}

// SupportsVersion reports whether this implementation can communicate using
// the given version. Currently only Version1 is supported.
func SupportsVersion(v Version) bool {
	return v == Version1
}
