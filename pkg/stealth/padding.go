package stealth

import (
	"fmt"

	"github.com/figox/figox-protocol/pkg/protocol"
)

// ApplyPadding fills f.Padding with random bytes and sets f.PadLength to the
// number of bytes added. It MUST be called before f.Encode: the padding bytes
// travel on the wire but are stripped by DecodeFrame and never affect the
// logical payload or the auth tag.
//
// The padding length is chosen by the engine (random or normalized per config)
// and is always clamped to [0, protocol.MaxPaddingLength] because PadLength is
// a uint8 field and the protocol cannot carry more than that.
//
// On any CSPRNG failure FillPadding returns an error; we fail closed and do NOT
// send a frame with deterministic (e.g. zero) padding, which would weaken the
// obfuscation and could be fingerprinted.
func ApplyPadding(f *protocol.Frame, e *Engine) error {
	if f == nil {
		return fmt.Errorf("fgxp/stealth: ApplyPadding: nil frame")
	}
	if e == nil {
		e = NewEngine(nil)
	}

	n := e.GeneratePadding()
	if n > protocol.MaxPaddingLength {
		// Defensive: GeneratePadding already clamps to MaxPad (<=255), but the
		// protocol wire field is uint8, so clamp again to be safe.
		n = protocol.MaxPaddingLength
	}
	// Clamp further so payload+padding still fits the 16-bit frame length field.
	// Realistic payloads are far below this limit, but we reduce padding rather
	// than let Encode reject (and the caller drop) a valid frame. Padding is
	// optional obfuscation, so shrinking it is safe.
	if maxPad := protocol.MaxPayloadLength - len(f.Payload); maxPad < int(n) {
		if maxPad < 0 {
			n = 0
		} else {
			n = uint8(maxPad)
		}
	}

	if n == 0 {
		f.PadLength = 0
		f.Padding = nil
		return nil
	}

	buf := make([]byte, n)
	if err := FillPadding(buf); err != nil {
		return fmt.Errorf("fgxp/stealth: ApplyPadding: fill padding: %w", err)
	}

	f.Padding = buf
	f.PadLength = n
	return nil
}
