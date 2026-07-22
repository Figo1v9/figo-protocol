package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/quic-go/quic-go"
)

// quicConn wraps a QUIC stream to implement the Conn interface.
// Each FGXP connection maps to a single QUIC connection, and the
// primary data exchange happens over a single bidirectional QUIC stream.
type quicConn struct {
	qconn  *quic.Conn
	stream *quic.Stream
}

// Verify interface compliance at compile time.
var _ Conn = (*quicConn)(nil)

func (c *quicConn) Read(b []byte) (int, error)  { return c.stream.Read(b) }
func (c *quicConn) Write(b []byte) (int, error) { return c.stream.Write(b) }

func (c *quicConn) Close() error {
	c.stream.Close()
	return c.qconn.CloseWithError(0, "close")
}

func (c *quicConn) LocalAddr() net.Addr  { return c.qconn.LocalAddr() }
func (c *quicConn) RemoteAddr() net.Addr { return c.qconn.RemoteAddr() }

func (c *quicConn) SetDeadline(t time.Time) error {
	if err := c.stream.SetReadDeadline(t); err != nil {
		return err
	}
	return c.stream.SetWriteDeadline(t)
}

func (c *quicConn) SetReadDeadline(t time.Time) error {
	return c.stream.SetReadDeadline(t)
}

func (c *quicConn) SetWriteDeadline(t time.Time) error {
	return c.stream.SetWriteDeadline(t)
}

func (c *quicConn) ConnectionState() tls.ConnectionState {
	return c.qconn.ConnectionState().TLS
}

func (c *quicConn) TransportType() Type { return QUIC }

// quicListener implements Listener for QUIC connections.
type quicListener struct {
	listener *quic.Listener
}

// Verify interface compliance at compile time.
var _ Listener = (*quicListener)(nil)

// ListenQUIC creates a QUIC listener on the given address.
func ListenQUIC(addr string, tlsCfg *tls.Config) (Listener, error) {
	if tlsCfg == nil {
		return nil, fmt.Errorf("fgxp/transport: TLS config is required for QUIC")
	}

	// QUIC requires ALPN. If not set, use h3 to look like HTTP/3.
	if len(tlsCfg.NextProtos) == 0 {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.NextProtos = []string{"h3"}
	}

	ln, err := quic.ListenAddr(addr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		Allow0RTT:       true,
		EnableDatagrams: false,
	})
	if err != nil {
		return nil, fmt.Errorf("fgxp/transport: listen quic %s: %w", addr, err)
	}
	return &quicListener{listener: ln}, nil
}

func (l *quicListener) Accept(ctx context.Context) (Conn, error) {
	qconn, err := l.listener.Accept(ctx)
	if err != nil {
		return nil, fmt.Errorf("fgxp/transport: quic accept: %w", err)
	}

	// Accept the first bidirectional stream from the client.
	// This stream carries all FGXP framing.
	stream, err := qconn.AcceptStream(ctx)
	if err != nil {
		qconn.CloseWithError(1, "no stream")
		return nil, fmt.Errorf("fgxp/transport: quic accept stream: %w", err)
	}

	return &quicConn{qconn: qconn, stream: stream}, nil
}

func (l *quicListener) Addr() net.Addr { return l.listener.Addr() }
func (l *quicListener) Close() error   { return l.listener.Close() }

// quicDialer implements Dialer for QUIC connections.
type quicDialer struct {
	tlsCfg *tls.Config
}

// Verify interface compliance at compile time.
var _ Dialer = (*quicDialer)(nil)

// NewQUICDialer creates a new QUIC dialer.
func NewQUICDialer(tlsCfg *tls.Config) Dialer {
	return &quicDialer{tlsCfg: tlsCfg}
}

func (d *quicDialer) Dial(ctx context.Context, addr string) (Conn, error) {
	tlsCfg := d.tlsCfg.Clone()
	if len(tlsCfg.NextProtos) == 0 {
		tlsCfg.NextProtos = []string{"h3"}
	}

	qconn, err := quic.DialAddr(ctx, addr, tlsCfg, &quic.Config{
		MaxIdleTimeout:  30 * time.Second,
		Allow0RTT:       true,
		EnableDatagrams: false,
	})
	if err != nil {
		return nil, fmt.Errorf("fgxp/transport: quic dial %s: %w", addr, err)
	}

	// Open the primary bidirectional stream.
	stream, err := qconn.OpenStreamSync(ctx)
	if err != nil {
		qconn.CloseWithError(1, "open stream failed")
		return nil, fmt.Errorf("fgxp/transport: quic open stream: %w", err)
	}

	return &quicConn{qconn: qconn, stream: stream}, nil
}
