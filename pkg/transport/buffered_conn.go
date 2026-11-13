package transport

import (
	"bufio"
	"net"
	"strings"
)

// bufferedNetConn preserves unread bytes inside a bufio.Reader so HTTP
// handshake or proxy parsers never discard pipelined application payload bytes.
type bufferedNetConn struct {
	net.Conn
	r *bufio.Reader
}

// NewBufferedNetConn wraps a net.Conn with a bufio.Reader for lossless subsequent reads.
func NewBufferedNetConn(conn net.Conn, r *bufio.Reader) net.Conn {
	if r == nil {
		return conn
	}
	return &bufferedNetConn{Conn: conn, r: r}
}

func (b *bufferedNetConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// BufferedTransportConn wraps a transport.Conn with a bufio.Reader so unread
// buffered bytes remain readable after HTTP header parsing or byte peeking.
type BufferedTransportConn struct {
	Conn
	r *bufio.Reader
}

// NewBufferedConn wraps a transport.Conn with a bufio.Reader.
func NewBufferedConn(conn Conn, r *bufio.Reader) *BufferedTransportConn {
	if r == nil {
		r = bufio.NewReader(conn)
	}
	return &BufferedTransportConn{Conn: conn, r: r}
}

func (b *BufferedTransportConn) Read(p []byte) (int, error) {
	return b.r.Read(p)
}

// Reader exposes the underlying bufio.Reader for zero-loss protocol parsing.
func (b *BufferedTransportConn) Reader() *bufio.Reader {
	return b.r
}

// EnsurePort normalizes host/IP inputs into host:port, preserving IPv6 brackets
// and appending defaultPort when missing or empty.
func EnsurePort(addr, defaultPort string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" || defaultPort == "" {
		return addr
	}
	if host, port, err := net.SplitHostPort(addr); err == nil {
		if port == "" {
			return net.JoinHostPort(host, defaultPort)
		}
		return addr
	}
	host := strings.TrimPrefix(strings.TrimSuffix(addr, "]"), "[")
	return net.JoinHostPort(host, defaultPort)
}

