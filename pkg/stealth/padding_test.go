package stealth

import (
	"bytes"
	"testing"

	"github.com/figox/figox-protocol/pkg/protocol"
)

// TestApplyPaddingRoundTrip verifies that a frame with random padding still
// decodes to the exact same payload and metadata after a full
// Encode -> Decode cycle. Padding must be lossless.
func TestApplyPaddingRoundTrip(t *testing.T) {
	eng := NewEngine(DefaultConfig())

	payloads := [][]byte{
		{},
		[]byte("hello fgxp"),
		bytes.Repeat([]byte("x"), 1000),
	}

	for _, p := range payloads {
		f := &protocol.Frame{
			Version:  protocol.Version1,
			Type:     protocol.FrameData,
			StreamID: 1,
			Payload:  p,
		}

		if err := ApplyPadding(f, eng); err != nil {
			t.Fatalf("ApplyPadding failed: %v", err)
		}

		// PadLength must be within protocol bounds.
		if f.PadLength > protocol.MaxPaddingLength {
			t.Fatalf("PadLength %d exceeds MaxPaddingLength %d", f.PadLength, protocol.MaxPaddingLength)
		}
		if int(f.PadLength) != len(f.Padding) {
			t.Fatalf("PadLength %d does not match padding slice len %d", f.PadLength, len(f.Padding))
		}

		encoded, err := f.Encode()
		if err != nil {
			t.Fatalf("Encode failed: %v", err)
		}

		decoded, err := protocol.DecodeFrameFromBytes(encoded)
		if err != nil {
			t.Fatalf("DecodeFrame failed: %v", err)
		}

		if decoded.Type != f.Type || decoded.StreamID != f.StreamID {
			t.Fatalf("decoded frame metadata mismatch: got %+v want %+v", decoded, f)
		}
		if !bytes.Equal(decoded.Payload, p) {
			t.Fatalf("decoded payload mismatch: got %q want %q", decoded.Payload, p)
		}
		// Decoded frame must have no padding retained in logical payload.
		if len(decoded.Payload) != len(p) {
			t.Fatalf("decoded payload length %d != original %d", len(decoded.Payload), len(p))
		}
	}
}

// TestApplyPaddingDisabled verifies that a disabled padding config produces a
// frame with zero padding.
func TestApplyPaddingDisabled(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Padding.Enabled = false
	eng := NewEngine(cfg)

	f := &protocol.Frame{
		Version: protocol.Version1,
		Type:    protocol.FrameData,
		Payload: []byte("no padding please"),
	}

	if err := ApplyPadding(f, eng); err != nil {
		t.Fatalf("ApplyPadding failed: %v", err)
	}
	if f.PadLength != 0 {
		t.Fatalf("expected PadLength 0 when disabled, got %d", f.PadLength)
	}
	if f.Padding != nil {
		t.Fatalf("expected nil padding when disabled, got %v", f.Padding)
	}
}
