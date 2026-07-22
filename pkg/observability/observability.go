// Package observability provides logging, metrics, tracing, and health checks
// for FGXP servers.
package observability

import (
	"context"
	"log/slog"
	"os"
	"sync/atomic"
	"time"
)

// Logger wraps slog for structured logging with FGXP-specific context.
type Logger struct {
	logger *slog.Logger
}

// NewLogger creates a new structured logger.
func NewLogger(level string, format string) *Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}

	opts := &slog.HandlerOptions{Level: lvl}
	var handler slog.Handler
	if format == "json" {
		handler = slog.NewJSONHandler(os.Stdout, opts)
	} else {
		handler = slog.NewTextHandler(os.Stdout, opts)
	}

	return &Logger{logger: slog.New(handler)}
}

// With returns a logger with additional context attributes.
func (l *Logger) With(args ...any) *Logger {
	return &Logger{logger: l.logger.With(args...)}
}

// Info logs at info level.
func (l *Logger) Info(msg string, args ...any) {
	l.logger.Info(msg, args...)
}

// Debug logs at debug level.
func (l *Logger) Debug(msg string, args ...any) {
	l.logger.Debug(msg, args...)
}

// Warn logs at warn level.
func (l *Logger) Warn(msg string, args ...any) {
	l.logger.Warn(msg, args...)
}

// Error logs at error level.
func (l *Logger) Error(msg string, args ...any) {
	l.logger.Error(msg, args...)
}

// Metrics tracks protocol-level counters and gauges.
type Metrics struct {
	// Connection metrics
	ActiveConnections   atomic.Int64
	TotalConnections    atomic.Int64
	FailedConnections   atomic.Int64

	// Stream metrics
	ActiveStreams        atomic.Int64
	TotalStreams         atomic.Int64

	// Data metrics
	BytesSent           atomic.Int64
	BytesReceived       atomic.Int64
	FramesSent          atomic.Int64
	FramesReceived      atomic.Int64

	// Auth metrics
	AuthSuccesses       atomic.Int64
	AuthFailures        atomic.Int64

	// Error metrics
	ProtocolErrors      atomic.Int64

	// Timing
	startTime           time.Time
}

// NewMetrics creates a new metrics collector.
func NewMetrics() *Metrics {
	return &Metrics{startTime: time.Now()}
}

// Uptime returns how long the server has been running.
func (m *Metrics) Uptime() time.Duration {
	return time.Since(m.startTime)
}

// Snapshot returns a point-in-time copy of all metrics.
func (m *Metrics) Snapshot() MetricsSnapshot {
	return MetricsSnapshot{
		ActiveConnections: m.ActiveConnections.Load(),
		TotalConnections:  m.TotalConnections.Load(),
		FailedConnections: m.FailedConnections.Load(),
		ActiveStreams:      m.ActiveStreams.Load(),
		TotalStreams:       m.TotalStreams.Load(),
		BytesSent:          m.BytesSent.Load(),
		BytesReceived:      m.BytesReceived.Load(),
		FramesSent:         m.FramesSent.Load(),
		FramesReceived:     m.FramesReceived.Load(),
		AuthSuccesses:      m.AuthSuccesses.Load(),
		AuthFailures:       m.AuthFailures.Load(),
		ProtocolErrors:     m.ProtocolErrors.Load(),
		Uptime:             m.Uptime(),
	}
}

// MetricsSnapshot is a point-in-time copy of metrics values.
type MetricsSnapshot struct {
	ActiveConnections int64
	TotalConnections  int64
	FailedConnections int64
	ActiveStreams      int64
	TotalStreams       int64
	BytesSent         int64
	BytesReceived     int64
	FramesSent        int64
	FramesReceived    int64
	AuthSuccesses     int64
	AuthFailures      int64
	ProtocolErrors    int64
	Uptime            time.Duration
}

// HealthChecker provides server health status.
type HealthChecker struct {
	metrics *Metrics
	ready   atomic.Bool
}

// NewHealthChecker creates a new health checker.
func NewHealthChecker(metrics *Metrics) *HealthChecker {
	return &HealthChecker{metrics: metrics}
}

// SetReady marks the server as ready to accept connections.
func (h *HealthChecker) SetReady(ready bool) {
	h.ready.Store(ready)
}

// IsHealthy reports whether the server is healthy.
func (h *HealthChecker) IsHealthy() bool {
	return true // Server is healthy if it's running.
}

// IsReady reports whether the server is ready to accept connections.
func (h *HealthChecker) IsReady() bool {
	return h.ready.Load()
}

// Tracer provides distributed tracing support.
// Currently a placeholder — full OpenTelemetry integration is deferred
// to v0.4.0 per the roadmap.
type Tracer struct {
	enabled  bool
	endpoint string
}

// NewTracer creates a new tracer.
func NewTracer(enabled bool, endpoint string) *Tracer {
	return &Tracer{enabled: enabled, endpoint: endpoint}
}

// StartSpan starts a new trace span. Returns the span context.
func (t *Tracer) StartSpan(ctx context.Context, name string) context.Context {
	if !t.enabled {
		return ctx
	}
	// OpenTelemetry integration point — deferred to v0.4.0.
	return ctx
}
