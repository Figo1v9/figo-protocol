// Package stealth implements FGXP's traffic obfuscation layer.
// It provides padding, timing normalization, and protocol mimicry
// to make FGXP traffic indistinguishable from normal HTTPS traffic.
package stealth

import (
	"crypto/rand"
	"math/big"
	"time"

	"github.com/figox/figox-protocol/pkg/protocol"
)

// Config holds stealth layer configuration.
type Config struct {
	// Padding controls random padding added to frames.
	Padding PaddingConfig

	// Timing controls inter-frame timing normalization.
	Timing TimingConfig

	// Camouflage configures the fallback server for active probes.
	Camouflage CamouflageConfig
}

// PaddingConfig controls how padding is added to frames.
type PaddingConfig struct {
	// Enabled activates padding.
	Enabled bool

	// Mode selects the padding strategy.
	// "random": uniform random padding between MinPad and MaxPad
	// "normalized": pad to nearest size class to match HTTPS patterns
	Mode string

	// MinPad is the minimum padding bytes (default: 0).
	MinPad int

	// MaxPad is the maximum padding bytes (default: 255).
	MaxPad int
}

// TimingConfig controls inter-frame timing.
type TimingConfig struct {
	// Enabled activates timing jitter.
	Enabled bool

	// MaxJitter is the maximum random delay added between frames.
	MaxJitter time.Duration
}

// CamouflageMode identifies how the server handles non-FGXP connections.
type CamouflageMode int

const (
	// CamouflageNone does not serve any camouflage content.
	CamouflageNone CamouflageMode = iota

	// CamouflageStatic serves static HTML files.
	CamouflageStatic

	// CamouflageReverseProxy proxies to a real backend.
	CamouflageReverseProxy
)

// DefaultServerHeader is the fallback HTTP Server header emitted by camouflage and WS responses.
const DefaultServerHeader = "nginx/1.25.3"

// CamouflageConfig configures the fallback handler for non-FGXP connections.
type CamouflageConfig struct {
	// Mode selects the camouflage strategy.
	Mode CamouflageMode

	// StaticDir is the directory of static files to serve (for CamouflageStatic).
	StaticDir string

	// ProxyTarget is the backend URL to proxy to (for CamouflageReverseProxy).
	ProxyTarget string

	// ServerHeader is the HTTP Server header value (default: "nginx/1.25.3").
	ServerHeader string
}

// DefaultConfig returns the default stealth configuration.
func DefaultConfig() *Config {
	return &Config{
		Padding: PaddingConfig{
			Enabled: true,
			Mode:    "random",
			MinPad:  0,
			MaxPad:  255,
		},
		Timing: TimingConfig{
			Enabled:   true,
			MaxJitter: 50 * time.Millisecond,
		},
		Camouflage: CamouflageConfig{
			Mode:         CamouflageStatic,
			ServerHeader: DefaultServerHeader,
		},
	}
}

// Engine applies stealth transformations to frames.
type Engine struct {
	cfg *Config
}

// NewEngine creates a new stealth engine with the given configuration.
func NewEngine(cfg *Config) *Engine {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return &Engine{cfg: cfg}
}

// SetPaddingMode switches the padding strategy at runtime. Used after the
// per-connection CONFIG negotiation (Stage 1) so the negotiated policy
// overrides the static config. Unknown modes fall back to random.
func (e *Engine) SetPaddingMode(mode protocol.PaddingMode) {
	if e.cfg == nil {
		e.cfg = DefaultConfig()
	}
	switch mode {
	case protocol.PaddingNormalized:
		e.cfg.Padding.Enabled = true
		e.cfg.Padding.Mode = "normalized"
	case protocol.PaddingNone:
		e.cfg.Padding.Enabled = false
	default:
		e.cfg.Padding.Enabled = true
		e.cfg.Padding.Mode = "random"
	}
}

// SetTiming switches inter-frame timing normalization at runtime and sets the
// maximum jitter. Used after CONFIG negotiation (Stage 2).
func (e *Engine) SetTiming(enabled bool, maxJitter time.Duration) {
	if e.cfg == nil {
		e.cfg = DefaultConfig()
	}
	e.cfg.Timing.Enabled = enabled
	if maxJitter >= 0 {
		e.cfg.Timing.MaxJitter = maxJitter
	}
}

// PaddingModeFromString maps a stealth padding mode string to the wire
// PaddingMode enum. Unknown strings fall back to random.
func PaddingModeFromString(s string) protocol.PaddingMode {
	switch s {
	case "normalized":
		return protocol.PaddingNormalized
	case "none":
		return protocol.PaddingNone
	default:
		return protocol.PaddingRandom
	}
}

// PaddingModeString renders the engine padding mode as the config string form.
func (e *Engine) PaddingModeString() string {
	if e.cfg == nil || !e.cfg.Padding.Enabled {
		return "none"
	}
	return e.cfg.Padding.Mode
}

// GeneratePadding returns a random padding length based on the current
// padding configuration.
func (e *Engine) GeneratePadding() uint8 {
	if !e.cfg.Padding.Enabled {
		return 0
	}

	minPad := e.cfg.Padding.MinPad
	maxPad := e.cfg.Padding.MaxPad
	if maxPad <= minPad {
		return uint8(minPad)
	}

	switch e.cfg.Padding.Mode {
	case "normalized":
		return e.normalizedPadding(minPad, maxPad)
	case "adaptive":
		shaper := NewAdaptiveShaper("web")
		return shaper.SamplePaddingLength(0, minPad, maxPad)
	default:
		return e.randomPadding(minPad, maxPad)
	}
}

// randomPadding generates a uniform random padding length.
func (e *Engine) randomPadding(min, max int) uint8 {
	diff := max - min
	n, err := rand.Int(rand.Reader, big.NewInt(int64(diff+1)))
	if err != nil {
		// Fallback to minimum on CSPRNG failure — should never happen.
		return uint8(min)
	}
	return uint8(min + int(n.Int64()))
}

// normalizedPadding pads to the nearest common HTTPS response size class
// to make traffic statistically similar to real web browsing.
//
// Common TLS record sizes observed in real HTTPS traffic:
//
//	~100 bytes  (small API responses, headers)
//	~500 bytes  (typical HTML fragment)
//	~1400 bytes (near MTU, common for streaming)
//	~4096 bytes (4KB chunks)
//	~8192 bytes (8KB chunks)
//	~16384 bytes (TLS max record, used by large downloads)
func (e *Engine) normalizedPadding(min, max int) uint8 {
	// For frame-level padding, we use small size classes since the
	// frame payload is already bounded by MaxPayloadLength.
	sizes := []int{0, 16, 32, 64, 128, 255}

	// Pick a random size class.
	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(sizes))))
	if err != nil {
		return uint8(min)
	}
	pad := sizes[idx.Int64()]

	// Clamp to configured range.
	if pad < min {
		pad = min
	}
	if pad > max {
		pad = max
	}
	return uint8(pad)
}

// GenerateTimingJitter returns a random delay to insert between frames.
// Returns 0 if timing jitter is disabled.
func (e *Engine) GenerateTimingJitter() time.Duration {
	if !e.cfg.Timing.Enabled || e.cfg.Timing.MaxJitter <= 0 {
		return 0
	}

	n, err := rand.Int(rand.Reader, big.NewInt(int64(e.cfg.Timing.MaxJitter)))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64())
}

// ApplyJitter sleeps for a random jitter duration if timing is enabled.
func (e *Engine) ApplyJitter() {
	jitter := e.GenerateTimingJitter()
	if jitter > 0 {
		time.Sleep(jitter)
	}
}

// FillPadding fills a byte slice with random bytes for use as frame padding.
func FillPadding(buf []byte) error {
	_, err := rand.Read(buf)
	return err
}

// IsHTTPMethodByte checks if a byte is the first character of an HTTP method.
// This is used by the camouflage system to detect HTTP probes.
//
// HTTP methods: GET, POST, PUT, DELETE, HEAD, OPTIONS, CONNECT, TRACE, PATCH
// First bytes:  G    P     P    D       H     O        C        T      P
func IsHTTPMethodByte(b byte) bool {
	switch b {
	case 'G', 'P', 'H', 'D', 'O', 'C', 'T':
		return true
	default:
		return false
	}
}
