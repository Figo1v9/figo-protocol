package protocol

import (
	"bytes"
	"testing"
)

func TestFrameRoundtrip(t *testing.T) {
	tests := []struct {
		name  string
		frame Frame
	}{
		{
			name: "DATA frame with payload",
			frame: Frame{
				Version:  Version1,
				Type:     FrameData,
				StreamID: 1,
				Sequence: 42,
				Flags:    0,
				Payload:  []byte("Hello, World!"),
			},
		},
		{
			name: "DATA frame with FIN",
			frame: Frame{
				Version:  Version1,
				Type:     FrameData,
				StreamID: 5,
				Sequence: 100,
				Flags:    Flags(FlagFIN),
				Payload:  []byte("goodbye"),
			},
		},
		{
			name: "AUTH frame on control stream",
			frame: Frame{
				Version:  Version1,
				Type:     FrameAuth,
				StreamID: ControlStreamID,
				Sequence: 0,
				Flags:    0,
				Payload:  []byte{0x01, 0x01, 0xAA, 0xBB},
			},
		},
		{
			name: "PING frame",
			frame: Frame{
				Version:  Version1,
				Type:     FramePing,
				StreamID: ControlStreamID,
				Sequence: 1,
				Flags:    0,
				Payload:  []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08},
			},
		},
		{
			name: "empty payload frame",
			frame: Frame{
				Version:  Version1,
				Type:     FrameStreamOpen,
				StreamID: 3,
				Sequence: 0,
				Flags:    0,
				Payload:  nil,
			},
		},
		{
			name: "frame with padding",
			frame: Frame{
				Version:   Version1,
				Type:      FrameData,
				StreamID:  7,
				Sequence:  10,
				Flags:     0,
				PadLength: 16,
				Payload:   []byte("padded data"),
			},
		},
		{
			name: "frame with multiple flags",
			frame: Frame{
				Version:  Version1,
				Type:     FrameData,
				StreamID: 2,
				Sequence: 1,
				Flags:    Flags(FlagFIN) | Flags(FlagCompressed),
				Payload:  []byte("compressed and final"),
			},
		},
		{
			name: "GOAWAY on control stream",
			frame: Frame{
				Version:  Version1,
				Type:     FrameGoAway,
				StreamID: ControlStreamID,
				Sequence: 0,
				Flags:    0,
				Payload:  []byte{0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00},
			},
		},
		{
			name: "server-initiated stream",
			frame: Frame{
				Version:  Version1,
				Type:     FrameData,
				StreamID: FirstServerStreamID,
				Sequence: 1,
				Flags:    0,
				Payload:  []byte("from server"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded, err := tt.frame.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}

			// Verify header size
			if len(encoded) < HeaderSize {
				t.Fatalf("encoded length %d < header size %d", len(encoded), HeaderSize)
			}

			// Decode from reader
			decoded, err := DecodeFrame(bytes.NewReader(encoded))
			if err != nil {
				t.Fatalf("DecodeFrame: %v", err)
			}

			assertFrameEqual(t, &tt.frame, decoded)

			// Decode from bytes
			decoded2, err := DecodeFrameFromBytes(encoded)
			if err != nil {
				t.Fatalf("DecodeFrameFromBytes: %v", err)
			}

			assertFrameEqual(t, &tt.frame, decoded2)
		})
	}
}

func TestFrameValidate(t *testing.T) {
	tests := []struct {
		name    string
		frame   Frame
		wantErr bool
	}{
		{
			name:    "valid DATA frame",
			frame:   Frame{Version: Version1, Type: FrameData, StreamID: 1},
			wantErr: false,
		},
		{
			name:    "DATA on control stream is invalid",
			frame:   Frame{Version: Version1, Type: FrameData, StreamID: 0},
			wantErr: true,
		},
		{
			name:    "GOAWAY must be on stream 0",
			frame:   Frame{Version: Version1, Type: FrameGoAway, StreamID: 5},
			wantErr: true,
		},
		{
			name:    "GOAWAY on stream 0 is valid",
			frame:   Frame{Version: Version1, Type: FrameGoAway, StreamID: 0},
			wantErr: false,
		},
		{
			name:    "AUTH must be on stream 0",
			frame:   Frame{Version: Version1, Type: FrameAuth, StreamID: 1},
			wantErr: true,
		},
		{
			name:    "reserved frame type is invalid",
			frame:   Frame{Version: Version1, Type: 0xC, StreamID: 0},
			wantErr: true,
		},
		{
			name:    "invalid version",
			frame:   Frame{Version: VersionInvalid, Type: FrameData, StreamID: 1},
			wantErr: true,
		},
		{
			name:    "reserved flags are invalid",
			frame:   Frame{Version: Version1, Type: FrameData, StreamID: 1, Flags: 0xC0},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.frame.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDecodeFrameTooShort(t *testing.T) {
	_, err := DecodeFrameFromBytes([]byte{0x10, 0x00})
	if err == nil {
		t.Fatal("expected error for short data")
	}
}

func TestDecodeFrameReservedNonZero(t *testing.T) {
	// Build a valid header but set reserved bytes to non-zero.
	hdr := make([]byte, HeaderSize)
	hdr[offVersionType] = 0x10 // v1, DATA
	// payload len = 0
	hdr[offReserved] = 0xFF // reserved non-zero
	_, err := DecodeFrameFromBytes(hdr)
	if err == nil {
		t.Fatal("expected error for non-zero reserved bytes")
	}
}

func TestFrameTotalSize(t *testing.T) {
	f := Frame{
		Version:   Version1,
		Type:      FrameData,
		StreamID:  1,
		PadLength: 10,
		Payload:   make([]byte, 100),
	}
	want := HeaderSize + 100 + 10
	if got := f.TotalSize(); got != want {
		t.Errorf("TotalSize() = %d, want %d", got, want)
	}
}

func TestFlagsOperations(t *testing.T) {
	var f Flags

	f = f.Set(FlagFIN)
	if !f.Has(FlagFIN) {
		t.Error("expected FIN to be set")
	}

	f = f.Set(FlagCompressed)
	if !f.Has(FlagCompressed) {
		t.Error("expected COMPRESSED to be set")
	}
	if !f.Has(FlagFIN) {
		t.Error("expected FIN to still be set")
	}

	f = f.Clear(FlagFIN)
	if f.Has(FlagFIN) {
		t.Error("expected FIN to be cleared")
	}
	if !f.Has(FlagCompressed) {
		t.Error("expected COMPRESSED to still be set")
	}
}

func TestFrameTypeString(t *testing.T) {
	if FrameData.String() != "DATA" {
		t.Errorf("FrameData.String() = %q", FrameData.String())
	}
	if FrameGoAway.String() != "GOAWAY" {
		t.Errorf("FrameGoAway.String() = %q", FrameGoAway.String())
	}
}

func TestErrorCodeString(t *testing.T) {
	if ErrNoError.String() != "NO_ERROR" {
		t.Errorf("got %q", ErrNoError.String())
	}
	if ErrAuthFailed.String() != "AUTH_FAILED" {
		t.Errorf("got %q", ErrAuthFailed.String())
	}
}

func TestVersionString(t *testing.T) {
	if Version1.String() != "FGXPv1" {
		t.Errorf("got %q", Version1.String())
	}
}

// assertFrameEqual compares two frames field-by-field.
func assertFrameEqual(t *testing.T, want, got *Frame) {
	t.Helper()
	if got.Version != want.Version {
		t.Errorf("Version: got %v, want %v", got.Version, want.Version)
	}
	if got.Type != want.Type {
		t.Errorf("Type: got %v, want %v", got.Type, want.Type)
	}
	if got.StreamID != want.StreamID {
		t.Errorf("StreamID: got %d, want %d", got.StreamID, want.StreamID)
	}
	if got.Sequence != want.Sequence {
		t.Errorf("Sequence: got %d, want %d", got.Sequence, want.Sequence)
	}
	if got.Flags != want.Flags {
		t.Errorf("Flags: got 0x%02X, want 0x%02X", got.Flags, want.Flags)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Errorf("Payload: got %q, want %q", got.Payload, want.Payload)
	}
}

func BenchmarkFrameEncode(b *testing.B) {
	f := Frame{
		Version:  Version1,
		Type:     FrameData,
		StreamID: 1,
		Sequence: 1,
		Payload:  make([]byte, 1024),
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = f.Encode()
	}
}

func BenchmarkFrameDecode(b *testing.B) {
	f := Frame{
		Version:  Version1,
		Type:     FrameData,
		StreamID: 1,
		Sequence: 1,
		Payload:  make([]byte, 1024),
	}
	data, _ := f.Encode()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = DecodeFrameFromBytes(data)
	}
}
