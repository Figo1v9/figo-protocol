// Package transport provides the Layer 1 abstraction for FGXP.
// It defines a common interface for TCP+TLS and QUIC transports,
// allowing the upper layers to operate transport-agnostically.
package transport

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"time"
)

// Type identifies the underlying transport protocol.
type Type int

const (
	// TCP uses TCP with TLS 1.3 encryption.
	TCP Type = iota

	// QUIC uses the QUIC protocol with built-in TLS 1.3.
	QUIC

	// Both enables listening on both TCP and QUIC simultaneously.
	// This is only valid for server configurations.
	Both
)

// String returns the transport type name.
func (t Type) String() string {
	switch t {
	case TCP:
		return "TCP"
	case QUIC:
		return "QUIC"
	case Both:
		return "TCP+QUIC"
	default:
		return "unknown"
	}
}

// Conn represents a single transport-layer connection. It abstracts
// the differences between a TCP+TLS connection and a QUIC connection,
// providing a unified byte-stream interface to the session layer.
//
// Implementations must be safe for concurrent Read and Write calls
// (one reader and one writer goroutine).
type Conn interface {
	io.ReadWriteCloser

	// LocalAddr returns the local network address.
	LocalAddr() net.Addr

	// RemoteAddr returns the remote network address.
	RemoteAddr() net.Addr

	// SetDeadline sets the read and write deadlines.
	SetDeadline(t time.Time) error

	// SetReadDeadline sets the read deadline.
	SetReadDeadline(t time.Time) error

	// SetWriteDeadline sets the write deadline.
	SetWriteDeadline(t time.Time) error

	// ConnectionState returns the TLS connection state.
	// For QUIC, this returns the TLS state of the QUIC handshake.
	ConnectionState() tls.ConnectionState

	// TransportType returns whether this is a TCP or QUIC connection.
	TransportType() Type
}

// Listener accepts incoming transport connections. It abstracts TCP
// and QUIC listeners behind a common interface.
type Listener interface {
	// Accept waits for and returns the next incoming connection.
	// The context allows cancellation of the accept operation.
	Accept(ctx context.Context) (Conn, error)

	// Addr returns the listener's network address.
	Addr() net.Addr

	// Close stops the listener. Any blocked Accept calls will return errors.
	Close() error
}

// Dialer creates outgoing transport connections.
type Dialer interface {
	// Dial establishes a new transport connection to the given address.
	Dial(ctx context.Context, addr string) (Conn, error)
}

// Config holds transport-layer configuration shared by TCP and QUIC.
type Config struct {
	// TLS is the TLS configuration. Required for both TCP and QUIC.
	TLS *tls.Config

	// Type selects the transport protocol.
	Type Type

	// KeepAlive enables TCP keepalive with the specified interval.
	// Ignored for QUIC (which has its own keepalive).
	KeepAlive time.Duration
}
