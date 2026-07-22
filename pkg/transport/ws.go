// Package transport provides the Layer 1 abstraction for FGXP.
// ws.go implements a WebSocket transport layer that wraps FGXP binary frames
// inside standard RFC 6455 WebSocket messages. This enables relay through
// Cloudflare Workers, CDN edge nodes, and any WebSocket-compatible proxy.
//
// Architecture:
//   Client --[WebSocket over TLS 1.3]--> Cloudflare Worker --[raw TCP]--> VPS FGXP Server
//
// The Cloudflare Worker accepts the WebSocket connection and relays binary
// messages to/from the FGXP server over a raw TCP socket. Because the outer
// layer is a standard WebSocket connection to a Cloudflare domain, ISP
// transparent proxies see legitimate Cloudflare traffic and allow it through.
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// wsConn wraps a gorilla/websocket.Conn to implement the transport.Conn interface.
// It presents a stream-oriented interface (Read/Write) on top of WebSocket's
// message-oriented protocol by buffering incoming messages.
type wsConn struct {
	ws     *websocket.Conn
	mu     sync.Mutex
	reader io.Reader // current message reader for partial reads
}

var _ Conn = (*wsConn)(nil)

func (c *wsConn) Read(b []byte) (int, error) {
	for {
		if c.reader != nil {
			n, err := c.reader.Read(b)
			if err == io.EOF {
				// Current message fully consumed, get next message
				c.reader = nil
				if n > 0 {
					return n, nil
				}
				continue
			}
			return n, err
		}
		// Get next WebSocket message
		_, reader, err := c.ws.NextReader()
		if err != nil {
			return 0, err
		}
		c.reader = reader
	}
}

func (c *wsConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	err := c.ws.WriteMessage(websocket.BinaryMessage, b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConn) Close() error {
	return c.ws.Close()
}

func (c *wsConn) LocalAddr() net.Addr {
	return c.ws.LocalAddr()
}

func (c *wsConn) RemoteAddr() net.Addr {
	return c.ws.RemoteAddr()
}

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.ws.SetReadDeadline(t); err != nil {
		return err
	}
	return c.ws.SetWriteDeadline(t)
}

func (c *wsConn) SetReadDeadline(t time.Time) error {
	return c.ws.SetReadDeadline(t)
}

func (c *wsConn) SetWriteDeadline(t time.Time) error {
	return c.ws.SetWriteDeadline(t)
}

func (c *wsConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{}
}

func (c *wsConn) TransportType() Type {
	return TCP
}

// DialWebSocketOptions configures the WebSocket transport with CDN Fronting support.
type DialWebSocketOptions struct {
	WSURL      string // Worker URL (e.g. wss://my-vpn-relay.mohamedkhedr974.workers.dev)
	SNI        string // TLS SNI for handshake spoofing (e.g. digital.gov.eg)
	HostHeader string // HTTP Host header for Cloudflare routing (e.g. my-vpn-relay.mohamedkhedr974.workers.dev)
	DialAddr   string // Optional target IP override to dial (e.g. Cloudflare IP 104.16.53.111)
}

// DialWebSocket connects to a WebSocket endpoint (typically a Cloudflare Worker)
// supporting full CDN Fronting (SNI spoofing + Worker routing).
func DialWebSocket(ctx context.Context, opts DialWebSocketOptions) (Conn, error) {
	u, err := url.Parse(opts.WSURL)
	if err != nil {
		return nil, fmt.Errorf("parse ws url: %w", err)
	}
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else if u.Scheme == "http" {
		u.Scheme = "ws"
	}
	if u.Scheme != "ws" && u.Scheme != "wss" {
		u.Scheme = "wss"
	}

	// Default Host header to the URL host if not specified
	hostHeader := opts.HostHeader
	if hostHeader == "" {
		hostHeader = u.Host
	}

	// Default SNI to HostHeader or URL host if not specified
	sniHost := opts.SNI
	if sniHost == "" {
		sniHost = u.Hostname()
	}

	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
		TLSClientConfig: &tls.Config{
			ServerName:         sniHost,
			InsecureSkipVerify: true,
		},
	}

	// Override NetDialContext if custom DialAddr or SNI is specified
	if opts.DialAddr != "" {
		dialer.NetDialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			netDialer := &net.Dialer{Timeout: 15 * time.Second}
			return netDialer.DialContext(ctx, network, opts.DialAddr)
		}
	}

	headers := http.Header{
		"Host":       {hostHeader},
		"User-Agent": {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"},
	}

	ws, _, err := dialer.DialContext(ctx, u.String(), headers)
	if err != nil {
		return nil, fmt.Errorf("websocket dial %s: %w", u.String(), err)
	}

	// Set generous limits for FGXP traffic
	ws.SetReadLimit(64 * 1024 * 1024) // 64MB max message

	return &wsConn{ws: ws}, nil
}
