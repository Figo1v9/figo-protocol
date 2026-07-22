// Package congestion defines the pluggable congestion control interface
// and provides built-in CUBIC and BBR implementations.
package congestion

import (
	"math"
	"sync"
	"time"
)

// Controller is the pluggable congestion control interface.
// Implementations MUST be safe for concurrent use.
type Controller interface {
	// OnPacketSent is called when a packet is sent.
	OnPacketSent(size int, sentTime time.Time)

	// OnAcknowledged is called when a packet is acknowledged.
	OnAcknowledged(size int, rtt time.Duration, ackTime time.Time)

	// OnPacketLost is called when a packet is detected as lost.
	OnPacketLost(size int, sentTime time.Time)

	// CongestionWindow returns the current window in bytes.
	CongestionWindow() int

	// CanSend reports whether sending 'bytes' would stay within the window.
	CanSend(bytes int) bool

	// SmoothedRTT returns the current smoothed RTT estimate.
	SmoothedRTT() time.Duration

	// Reset resets the controller to initial state.
	Reset()
}

// Noop is a no-op congestion controller used when QUIC handles CC natively.
type Noop struct{}

func (Noop) OnPacketSent(int, time.Time)               {}
func (Noop) OnAcknowledged(int, time.Duration, time.Time) {}
func (Noop) OnPacketLost(int, time.Time)                {}
func (Noop) CongestionWindow() int                      { return math.MaxInt32 }
func (Noop) CanSend(int) bool                           { return true }
func (Noop) SmoothedRTT() time.Duration                 { return 0 }
func (Noop) Reset()                                     {}

// Verify interface compliance.
var _ Controller = Noop{}

// CUBIC implements the CUBIC congestion control algorithm (RFC 8312).
// This is a simplified implementation suitable for application-layer rate control.
type CUBIC struct {
	mu sync.Mutex

	// State
	cwnd       int           // current congestion window (bytes)
	ssthresh   int           // slow-start threshold
	bytesInFlight int        // bytes sent but not yet acknowledged
	srtt       time.Duration // smoothed RTT
	rttvar     time.Duration // RTT variance

	// CUBIC-specific
	lastMaxCwnd int         // cwnd at last loss event
	epochStart  time.Time   // start of current CUBIC epoch
	originPoint int         // W_max at epoch start
	k           float64     // time to reach W_max

	// Configuration
	initialCwnd int // initial window size
	minCwnd     int // minimum window size
}

// CUBIC constants.
const (
	cubicBeta = 0.7  // Multiplicative decrease factor
	cubicC    = 0.4  // CUBIC scaling constant
)

// NewCUBIC creates a new CUBIC congestion controller.
func NewCUBIC() *CUBIC {
	initialCwnd := 10 * 1460 // 10 MSS segments
	return &CUBIC{
		cwnd:        initialCwnd,
		ssthresh:    math.MaxInt32,
		initialCwnd: initialCwnd,
		minCwnd:     2 * 1460,
	}
}

// Verify interface compliance.
var _ Controller = (*CUBIC)(nil)

func (c *CUBIC) OnPacketSent(size int, sentTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.bytesInFlight += size
}

func (c *CUBIC) OnAcknowledged(size int, rtt time.Duration, ackTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.bytesInFlight -= size
	if c.bytesInFlight < 0 {
		c.bytesInFlight = 0
	}

	c.updateRTT(rtt)

	if c.cwnd < c.ssthresh {
		// Slow start: increase by 1 MSS per ACK
		c.cwnd += size
	} else {
		// Congestion avoidance: CUBIC growth
		c.cubicUpdate(ackTime)
	}
}

func (c *CUBIC) OnPacketLost(size int, sentTime time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.bytesInFlight -= size
	if c.bytesInFlight < 0 {
		c.bytesInFlight = 0
	}

	// Multiplicative decrease
	c.lastMaxCwnd = c.cwnd
	c.ssthresh = int(float64(c.cwnd) * cubicBeta)
	if c.ssthresh < c.minCwnd {
		c.ssthresh = c.minCwnd
	}
	c.cwnd = c.ssthresh
	c.epochStart = time.Time{} // Reset epoch
}

func (c *CUBIC) CongestionWindow() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.cwnd
}

func (c *CUBIC) CanSend(bytes int) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bytesInFlight+bytes <= c.cwnd
}

func (c *CUBIC) SmoothedRTT() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.srtt
}

func (c *CUBIC) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cwnd = c.initialCwnd
	c.ssthresh = math.MaxInt32
	c.bytesInFlight = 0
	c.srtt = 0
	c.rttvar = 0
	c.lastMaxCwnd = 0
	c.epochStart = time.Time{}
	c.originPoint = 0
	c.k = 0
}

// updateRTT updates the smoothed RTT using Jacobson's algorithm.
func (c *CUBIC) updateRTT(rtt time.Duration) {
	if c.srtt == 0 {
		c.srtt = rtt
		c.rttvar = rtt / 2
		return
	}
	// RTTVAR = (1-beta) * RTTVAR + beta * |SRTT - RTT|
	diff := c.srtt - rtt
	if diff < 0 {
		diff = -diff
	}
	c.rttvar = (3*c.rttvar + diff) / 4
	// SRTT = (1-alpha) * SRTT + alpha * RTT
	c.srtt = (7*c.srtt + rtt) / 8
}

// cubicUpdate applies the CUBIC window growth function.
func (c *CUBIC) cubicUpdate(now time.Time) {
	if c.epochStart.IsZero() {
		c.epochStart = now
		if c.lastMaxCwnd <= c.cwnd {
			c.k = 0
			c.originPoint = c.cwnd
		} else {
			c.k = math.Cbrt(float64(c.lastMaxCwnd-c.cwnd) / cubicC)
			c.originPoint = c.lastMaxCwnd
		}
	}

	elapsed := now.Sub(c.epochStart).Seconds()
	// W_cubic(t) = C * (t - K)^3 + W_max
	target := cubicC*math.Pow(elapsed-c.k, 3) + float64(c.originPoint)
	if target > float64(c.cwnd) {
		c.cwnd = int(target)
	} else {
		// TCP-friendly region
		c.cwnd += 1460 / c.cwnd
	}
}
