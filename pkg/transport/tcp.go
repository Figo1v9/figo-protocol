package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// tcpConn wraps a TLS connection over TCP to implement the Conn interface.
type tcpConn struct {
	conn *tls.Conn
}

// Verify interface compliance at compile time.
var _ Conn = (*tcpConn)(nil)

func (c *tcpConn) Read(b []byte) (int, error)  { return c.conn.Read(b) }
func (c *tcpConn) Write(b []byte) (int, error) { return c.conn.Write(b) }
func (c *tcpConn) Close() error                { return c.conn.Close() }
func (c *tcpConn) LocalAddr() net.Addr         { return c.conn.LocalAddr() }
func (c *tcpConn) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }

func (c *tcpConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *tcpConn) SetReadDeadline(t time.Time) error   { return c.conn.SetReadDeadline(t) }
func (c *tcpConn) SetWriteDeadline(t time.Time) error  { return c.conn.SetWriteDeadline(t) }

func (c *tcpConn) ConnectionState() tls.ConnectionState {
	return c.conn.ConnectionState()
}

func (c *tcpConn) TransportType() Type { return TCP }

// tcpListener implements Listener for TCP+TLS connections.
type tcpListener struct {
	listener net.Listener
	tlsCfg   *tls.Config
}

// Verify interface compliance at compile time.
var _ Listener = (*tcpListener)(nil)

// ListenTCP creates a TCP+TLS listener on the given address.
func ListenTCP(addr string, tlsCfg *tls.Config) (Listener, error) {
	if tlsCfg == nil {
		return nil, fmt.Errorf("fgxp/transport: TLS config is required for TCP")
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fgxp/transport: listen tcp %s: %w", addr, err)
	}
	tlsLn := tls.NewListener(ln, tlsCfg)
	return &tcpListener{listener: tlsLn, tlsCfg: tlsCfg}, nil
}

func (l *tcpListener) Accept(ctx context.Context) (Conn, error) {
	// Use a goroutine to make Accept cancellable via context.
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := l.listener.Accept()
		ch <- result{conn, err}
	}()

	select {
	case <-ctx.Done():
		// Context cancelled; close listener to unblock Accept.
		// The next call will fail, which is expected.
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("fgxp/transport: accept: %w", r.err)
		}
		tlsConn, ok := r.conn.(*tls.Conn)
		if !ok {
			r.conn.Close()
			return nil, fmt.Errorf("fgxp/transport: expected TLS conn, got %T", r.conn)
		}
		return &tcpConn{conn: tlsConn}, nil
	}
}

func (l *tcpListener) Addr() net.Addr { return l.listener.Addr() }
func (l *tcpListener) Close() error   { return l.listener.Close() }

// tcpDialer implements Dialer for TCP+TLS connections.
type tcpDialer struct {
	tlsCfg    *tls.Config
	keepAlive time.Duration
}

// Verify interface compliance at compile time.
var _ Dialer = (*tcpDialer)(nil)

// NewTCPDialer creates a new TCP+TLS dialer.
func NewTCPDialer(tlsCfg *tls.Config, keepAlive time.Duration) Dialer {
	return &tcpDialer{tlsCfg: tlsCfg, keepAlive: keepAlive}
}

func (d *tcpDialer) Dial(ctx context.Context, addr string) (Conn, error) {
	dialer := &net.Dialer{
		KeepAlive: d.keepAlive,
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fgxp/transport: dial tcp %s: %w", addr, err)
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(4194304)  // 4MB socket receive buffer
		_ = tcpConn.SetWriteBuffer(4194304) // 4MB socket send buffer
	}

	conn := tls.Client(rawConn, d.tlsCfg)

	// Perform TLS handshake with context deadline.
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	if err := conn.HandshakeContext(ctx); err != nil {
		conn.Close()
		return nil, fmt.Errorf("fgxp/transport: tls handshake: %w", err)
	}
	// Clear deadline after successful handshake.
	conn.SetDeadline(time.Time{})

	return &tcpConn{conn: conn}, nil
}

// rawTCPConn wraps a net.Conn for non-TLS Plaintext TCP connections.
type rawTCPConn struct {
	net.Conn
}

func (r *rawTCPConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{}
}

func (r *rawTCPConn) TransportType() Type {
	return TCP
}

// DialRawTCP dials a raw TCP connection without a TLS wrapper.
func DialRawTCP(ctx context.Context, addr string) (Conn, error) {
	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fgxp/transport: dial raw tcp %s: %w", addr, err)
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(4194304)  // 4MB receive buffer
		_ = tcpConn.SetWriteBuffer(4194304) // 4MB send buffer
	}

	return &rawTCPConn{Conn: rawConn}, nil
}

// rawTCPListener implements Listener for non-TLS TCP connections.
type rawTCPListener struct {
	listener net.Listener
}

func (l *rawTCPListener) Accept(ctx context.Context) (Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		conn, err := l.listener.Accept()
		ch <- result{conn, err}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-ch:
		if r.err != nil {
			return nil, fmt.Errorf("fgxp/transport: accept raw tcp: %w", r.err)
		}
		return &rawTCPConn{Conn: r.conn}, nil
	}
}

func (l *rawTCPListener) Addr() net.Addr { return l.listener.Addr() }
func (l *rawTCPListener) Close() error   { return l.listener.Close() }

// ListenRawTCP creates a raw TCP listener without a TLS wrapper.
func ListenRawTCP(addr string) (Listener, error) {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("fgxp/transport: listen raw tcp %s: %w", addr, err)
	}
	return &rawTCPListener{listener: ln}, nil
}
