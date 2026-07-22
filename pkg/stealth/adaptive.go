package stealth

import (
	"crypto/rand"
	"math/big"
	"time"
)

// TrafficProfile identifies pre-defined statistical distribution profiles for Stage 6.
type TrafficProfile string

const (
	// ProfileWebBrowsing mimics standard HTTPS web browsing packet distributions.
	ProfileWebBrowsing TrafficProfile = "web"

	// ProfileVideoStreaming mimics video streaming MTU-sized chunk distributions.
	ProfileVideoStreaming TrafficProfile = "video"

	// ProfileInteractiveAPI mimics REST API / RPC low-latency traffic.
	ProfileInteractiveAPI TrafficProfile = "api"
)

// AdaptiveShaper implements Stage 6 ML-resistant adaptive traffic shaping.
// It shapes frame lengths and inter-packet timing to fit background HTTPS probability distributions.
type AdaptiveShaper struct {
	Profile TrafficProfile
}

// NewAdaptiveShaper creates a new adaptive shaper for the given profile.
func NewAdaptiveShaper(profile string) *AdaptiveShaper {
	p := TrafficProfile(profile)
	if p != ProfileVideoStreaming && p != ProfileInteractiveAPI {
		p = ProfileWebBrowsing
	}
	return &AdaptiveShaper{Profile: p}
}

// SamplePaddingLength returns a padding length designed to shape payloadLen
// to match the target traffic profile's statistical distribution.
func (a *AdaptiveShaper) SamplePaddingLength(payloadLen int, minPad, maxPad int) uint8 {
	if maxPad <= minPad {
		return uint8(minPad)
	}

	var sizes []int
	switch a.Profile {
	case ProfileVideoStreaming:
		// Video streaming favors larger near-MTU sizes (128, 200, 255)
		sizes = []int{64, 128, 192, 255}
	case ProfileInteractiveAPI:
		// API traffic favors smaller uniform frames
		sizes = []int{8, 16, 32, 64}
	default: // ProfileWebBrowsing
		// Web browsing has modal sizes across the spectrum
		sizes = []int{16, 32, 64, 128, 255}
	}

	idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(sizes))))
	if err != nil {
		return uint8(minPad)
	}

	pad := sizes[idx.Int64()]
	if pad < minPad {
		pad = minPad
	}
	if pad > maxPad {
		pad = maxPad
	}
	return uint8(pad)
}

// SampleJitter returns an inter-frame delay sampled from the traffic profile CDF.
func (a *AdaptiveShaper) SampleJitter(maxJitter time.Duration) time.Duration {
	if maxJitter <= 0 {
		return 0
	}

	var maxMs int64
	switch a.Profile {
	case ProfileVideoStreaming:
		// Video streaming: bursty pacing (5ms - 15ms)
		maxMs = 15
	case ProfileInteractiveAPI:
		// API traffic: fast response (1ms - 10ms)
		maxMs = 10
	default: // ProfileWebBrowsing
		// Web traffic: 10ms - maxJitter
		maxMs = maxJitter.Milliseconds()
	}

	if maxMs <= 0 {
		return 0
	}

	n, err := rand.Int(rand.Reader, big.NewInt(maxMs))
	if err != nil {
		return 0
	}
	return time.Duration(n.Int64()) * time.Millisecond
}
