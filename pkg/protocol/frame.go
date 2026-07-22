package protocol

import (
	"encoding/binary"
	"fmt"
	"io"
)

// Frame represents a decoded FGXP frame with its 16-byte header and payload.
//
// Wire format (16-byte header):
//
//	 0                   1                   2                   3
//	 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|Version|  Type |         Payload Length (16)                    |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                       Stream ID (32)                          |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|                    Sequence Number (32)                        |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//	|    Flags (8)  |  Pad Len (8)  |      Reserved (16)            |
//	+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
type Frame struct {
	Version    Version
	Type       FrameType
	StreamID   uint32
	Sequence   uint32
	Flags      Flags
	PadLength  uint8
	Padding    []byte // Random obfuscation bytes; stripped by DecodeFrame and never part of the logical payload or auth tag.
	Payload    []byte // Application data (excluding padding)
}

// headerOffsets define byte positions within the 16-byte header.
const (
	offVersionType = 0  // byte 0: high nibble = version, low nibble = type
	offPayloadLen  = 1  // bytes 1-2: payload length (big-endian)
	offStreamID    = 3  // bytes 3-6: stream ID (big-endian)
	offSequence    = 7  // bytes 7-10: sequence number (big-endian)
	offFlags       = 11 // byte 11: flags
	offPadLen      = 12 // byte 12: padding length
	offReserved    = 13 // bytes 13-14: reserved (must be 0)
)

// Encode serializes the frame into wire format. The returned slice contains
// the 16-byte header followed by the payload and any padding carried in
// f.Padding. The stealth layer populates f.Padding and f.PadLength via
// ApplyPadding immediately before Encode is called.
//
// The caller must ensure that len(f.Payload) + int(f.PadLength) fits in
// a uint16 (max 65535); otherwise Encode returns a protocol error.
func (f *Frame) Encode() ([]byte, error) {
	dataLen := len(f.Payload) + int(f.PadLength)
	if dataLen > MaxPayloadLength {
		return nil, NewProtocolErrorf(ErrFrameSize,
			"payload+padding %d exceeds max %d", dataLen, MaxPayloadLength)
	}

	buf := make([]byte, HeaderSize+dataLen)
	f.encodeHeaderInto(buf, uint16(dataLen))
	copy(buf[HeaderSize:], f.Payload)
	// Wire in the random padding chosen by the stealth layer (L3). DecodeFrame
	// strips it before reconstruction, so it never affects the logical payload
	// or the auth tag. When no padding is applied the region stays zero-filled,
	// preserving the pre-stealth wire format for non-padded frames.
	if n := int(f.PadLength); n > 0 && len(f.Padding) > 0 {
		padStart := HeaderSize + len(f.Payload)
		copy(buf[padStart:padStart+n], f.Padding)
	}
	return buf, nil
}

// EncodeHeader writes only the 16-byte header into buf. buf must be at least
// HeaderSize bytes. payloadLen is the combined length of payload + padding.
func (f *Frame) encodeHeaderInto(buf []byte, payloadLen uint16) {
	buf[offVersionType] = (byte(f.Version) << 4) | (byte(f.Type) & 0x0F)
	binary.BigEndian.PutUint16(buf[offPayloadLen:], payloadLen)
	binary.BigEndian.PutUint32(buf[offStreamID:], f.StreamID)
	binary.BigEndian.PutUint32(buf[offSequence:], f.Sequence)
	buf[offFlags] = byte(f.Flags)
	buf[offPadLen] = f.PadLength
	buf[offReserved] = 0
	buf[offReserved+1] = 0
}

// EncodeTo writes the frame to w. It is equivalent to Encode followed by
// w.Write but avoids an extra allocation when the writer supports
// io.ReaderFrom or similar optimizations.
func (f *Frame) EncodeTo(w io.Writer) (int64, error) {
	data, err := f.Encode()
	if err != nil {
		return 0, err
	}
	n, err := w.Write(data)
	return int64(n), err
}

// DecodeFrame reads a complete frame from r. It first reads the 16-byte header,
// then reads the payload (including padding). The returned Frame's Payload
// contains only the application data (padding is stripped).
func DecodeFrame(r io.Reader) (*Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, fmt.Errorf("fgxp: read header: %w", err)
	}

	f := &Frame{}
	if err := f.decodeHeader(hdr[:]); err != nil {
		return nil, err
	}

	payloadLen := binary.BigEndian.Uint16(hdr[offPayloadLen:])
	if payloadLen == 0 {
		f.Payload = nil
		return f, nil
	}

	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, fmt.Errorf("fgxp: read payload: %w", err)
	}

	// Strip padding: payload data is payload[0 : payloadLen - padLen]
	dataEnd := int(payloadLen) - int(f.PadLength)
	if dataEnd < 0 {
		return nil, NewProtocolError(ErrFrameFormat, "pad length exceeds payload length")
	}
	f.Payload = payload[:dataEnd]

	return f, nil
}

// DecodeFrameFromBytes decodes a frame from a byte slice. This is useful for
// testing and for processing pre-buffered data.
func DecodeFrameFromBytes(data []byte) (*Frame, error) {
	if len(data) < HeaderSize {
		return nil, NewProtocolErrorf(ErrFrameFormat,
			"data too short: %d bytes, need at least %d", len(data), HeaderSize)
	}

	f := &Frame{}
	if err := f.decodeHeader(data[:HeaderSize]); err != nil {
		return nil, err
	}

	payloadLen := binary.BigEndian.Uint16(data[offPayloadLen:])
	totalLen := HeaderSize + int(payloadLen)
	if len(data) < totalLen {
		return nil, NewProtocolErrorf(ErrFrameFormat,
			"data too short: %d bytes, frame requires %d", len(data), totalLen)
	}

	if payloadLen == 0 {
		f.Payload = nil
		return f, nil
	}

	dataEnd := int(payloadLen) - int(f.PadLength)
	if dataEnd < 0 {
		return nil, NewProtocolError(ErrFrameFormat, "pad length exceeds payload length")
	}
	f.Payload = make([]byte, dataEnd)
	copy(f.Payload, data[HeaderSize:HeaderSize+dataEnd])

	return f, nil
}

// decodeHeader parses the 16-byte header into the frame's fields.
func (f *Frame) decodeHeader(hdr []byte) error {
	vt := hdr[offVersionType]
	f.Version = Version(vt >> 4)
	f.Type = FrameType(vt & 0x0F)
	f.StreamID = binary.BigEndian.Uint32(hdr[offStreamID:])
	f.Sequence = binary.BigEndian.Uint32(hdr[offSequence:])
	f.Flags = Flags(hdr[offFlags])
	f.PadLength = hdr[offPadLen]

	// Validate reserved bytes are zero.
	if hdr[offReserved] != 0 || hdr[offReserved+1] != 0 {
		return NewProtocolError(ErrFrameFormat, "reserved bytes must be zero")
	}

	// Validate reserved flag bits.
	if !f.Flags.IsValid() {
		return NewProtocolError(ErrFrameFormat, "reserved flag bits are set")
	}

	return nil
}

// TotalSize returns the total wire size of this frame (header + payload + padding).
func (f *Frame) TotalSize() int {
	return HeaderSize + len(f.Payload) + int(f.PadLength)
}

// IsControl reports whether this frame is sent on the control stream (stream 0).
func (f *Frame) IsControl() bool {
	return f.StreamID == ControlStreamID
}

// Validate performs basic validation of the frame structure.
// It checks version, type, flags, and stream ID constraints.
func (f *Frame) Validate() error {
	if !f.Version.IsValid() && f.Version != VersionNegotiation {
		return NewProtocolErrorf(ErrInvalidVersion, "version 0x%X", f.Version)
	}

	if f.Type.IsReserved() {
		return NewProtocolErrorf(ErrInvalidFrameType, "reserved type 0x%X", f.Type)
	}

	if !f.Flags.IsValid() {
		return NewProtocolError(ErrFrameFormat, "reserved flag bits are set")
	}

	// Control frames must be on stream 0.
	switch f.Type {
	case FrameGoAway, FrameAuth, FrameSessionResume, FrameConfig:
		if f.StreamID != ControlStreamID {
			return NewProtocolErrorf(ErrInvalidStreamID,
				"%s frame must be on stream 0, got %d", f.Type, f.StreamID)
		}
	case FrameData:
		if f.StreamID == ControlStreamID {
			return NewProtocolError(ErrInvalidStreamID,
				"DATA frame must not be on stream 0")
		}
	}

	return nil
}
