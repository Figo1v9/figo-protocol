// Package transport provides the Layer 1 abstraction for FGXP.
// ws.go implements bidirectional RFC 6455 WebSocket transport with browser uTLS
// mimicry (client) and probe-safe HTTP upgrade validation (server), supporting
// Imperva, Cloudflare, Nginx, and Cloudflare Worker relays.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

const defaultWSPingTimeout = 10 * time.Second

// wsConn wraps a gorilla/websocket.Conn to implement the transport.Conn interface.
// Writes and write-deadlines share c.mu because gorilla/websocket does not lock
// around its internal writeDeadline field during concurrent WriteMessage calls.
type wsConn struct {
	ws         *websocket.Conn
	mu         sync.Mutex
	reader     io.Reader
	tlsState   tls.ConnectionState
	remoteAddr net.Addr
	stopOnce   sync.Once
	stopCh     chan struct{}
}

var _ Conn = (*wsConn)(nil)

// WrapWebSocketConn adapts a negotiated *websocket.Conn into a transport.Conn.
func WrapWebSocketConn(ws *websocket.Conn, remoteAddr net.Addr, tlsState tls.ConnectionState) Conn {
	if remoteAddr == nil && ws != nil {
		remoteAddr = ws.RemoteAddr()
	}
	return &wsConn{
		ws:         ws,
		tlsState:   tlsState,
		remoteAddr: remoteAddr,
		stopCh:     make(chan struct{}),
	}
}

// StartKeepAlive sends periodic RFC 6455 Ping control frames to keep CDN edges
// (such as Imperva and Cloudflare) from reaping idle WebSocket tunnels.
func (c *wsConn) StartKeepAlive(interval time.Duration) {
	if interval <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				// gorilla/websocket permits concurrent WriteControl alongside WriteMessage.
				if err := c.ws.WriteControl(websocket.PingMessage, nil, time.Now().Add(defaultWSPingTimeout)); err != nil {
					_ = c.Close()
					return
				}
			}
		}
	}()
}

func (c *wsConn) Read(b []byte) (int, error) {
	for {
		if c.reader != nil {
			n, err := c.reader.Read(b)
			if err == io.EOF {
				c.reader = nil
				if n > 0 {
					return n, nil
				}
				continue
			}
			return n, err
		}
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
	if err := c.ws.WriteMessage(websocket.BinaryMessage, b); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *wsConn) Close() error {
	c.stopOnce.Do(func() {
		if c.stopCh != nil {
			close(c.stopCh)
		}
	})
	return c.ws.Close()
}

func (c *wsConn) LocalAddr() net.Addr {
	return c.ws.LocalAddr()
}

func (c *wsConn) RemoteAddr() net.Addr {
	if c.remoteAddr != nil {
		return c.remoteAddr
	}
	return c.ws.RemoteAddr()
}

func (c *wsConn) SetDeadline(t time.Time) error {
	if err := c.SetReadDeadline(t); err != nil {
		return err
	}
	return c.SetWriteDeadline(t)
}

func (c *wsConn) SetReadDeadline(t time.Time) error {
	return c.ws.SetReadDeadline(t)
}

func (c *wsConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ws.SetWriteDeadline(t)
}

func (c *wsConn) ConnectionState() tls.ConnectionState {
	return c.tlsState
}

func (c *wsConn) TransportType() Type {
	return TCP
}

// IsWebSocketUpgradeRequest verifies RFC 6455 client upgrade preconditions
// before calling gorilla/websocket.Upgrader so active HTTP probes never
// receive gorilla/websocket's telltale 400/405 error responses.
func IsWebSocketUpgradeRequest(r *http.Request) bool {
	if r == nil || r.Method != http.MethodGet || !r.ProtoAtLeast(1, 1) {
		return false
	}
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false
	}
	if !headerContainsToken(r.Header.Values("Connection"), "upgrade") {
		return false
	}
	if strings.TrimSpace(r.Header.Get("Sec-WebSocket-Version")) != "13" {
		return false
	}
	rawKey, err := base64.StdEncoding.DecodeString(strings.TrimSpace(r.Header.Get("Sec-WebSocket-Key")))
	return err == nil && len(rawKey) == 16
}

func headerContainsToken(values []string, target string) bool {
	for _, val := range values {
		for _, part := range strings.Split(val, ",") {
			if strings.EqualFold(strings.TrimSpace(part), target) {
				return true
			}
		}
	}
	return false
}

// DialWebSocketOptions configures the WebSocket transport with uTLS and CDN Fronting.
type DialWebSocketOptions struct {
	WSURL              string        // e.g. wss://cdn.example.com/ws-secret or ws://1.2.3.4/ws-secret
	SNI                string        // TLS SNI for handshake mimicry/fronting
	HostHeader         string        // HTTP Host header override (decoupled from SNI and DialAddr)
	DialAddr           string        // Optional target IP[:port] override (e.g. Cloudflare/Imperva edge IP)
	Fingerprint        string        // Browser TLS fingerprint: chrome, firefox, edge, randomized, none
	InsecureSkipVerify bool          // Allow self-signed / mismatched SAN certificates
	RootCAs            *x509.CertPool
	PingInterval       time.Duration // RFC 6455 Ping interval (default 20s when > 0)
}

// DialWebSocket connects to an RFC 6455 WebSocket endpoint using uTLS (HTTP/1.1
// ALPN) for wss:// and full CDN SNI/Host/IP decoupling.
func DialWebSocket(ctx context.Context, opts DialWebSocketOptions) (Conn, error) {
	u, err := url.Parse(strings.TrimSpace(opts.WSURL))
	if err != nil {
		return nil, fmt.Errorf("parse ws url: %w", err)
	}
	switch strings.ToLower(u.Scheme) {
	case "https", "wss", "":
		u.Scheme = "wss"
	case "http", "ws":
		u.Scheme = "ws"
	default:
		u.Scheme = "wss"
	}

	httpScheme := "https"
	defaultPort := "443"
	if u.Scheme == "ws" {
		httpScheme = "http"
		defaultPort = "80"
	}

	hostHeader := strings.TrimSpace(opts.HostHeader)
	if hostHeader == "" {
		hostHeader = StripDefaultPort(u.Host, httpScheme)
	} else {
		hostHeader = StripDefaultPort(hostHeader, httpScheme)
	}

	sniHost := strings.TrimSpace(opts.SNI)
	if sniHost != "" {
		if parsed, parseErr := ParseTransportURL(sniHost); parseErr == nil {
			sniHost = parsed.Hostname
		}
	} else {
		sniHost = u.Hostname()
	}

	dialTarget := strings.TrimSpace(opts.DialAddr)
	if dialTarget == "" {
		dialTarget = EnsurePort(u.Host, defaultPort)
	} else {
		dialTarget = EnsurePort(dialTarget, defaultPort)
	}

	var negotiatedState tls.ConnectionState
	var stateMu sync.Mutex

	dialer := websocket.Dialer{
		HandshakeTimeout: 15 * time.Second,
	}

	if u.Scheme == "wss" {
		tlsCfg := &tls.Config{
			ServerName:         sniHost,
			InsecureSkipVerify: opts.InsecureSkipVerify,
			RootCAs:            opts.RootCAs,
			NextProtos:         []string{"http/1.1"},
		}
		fp := opts.Fingerprint
		if fp == "" {
			fp = FingerprintChrome
		}
		dialer.NetDialTLSContext = func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			conn, state, dialErr := DialUTLSHTTP1(dialCtx, dialTarget, tlsCfg, fp)
			if dialErr != nil {
				return nil, dialErr
			}
			stateMu.Lock()
			negotiatedState = state
			stateMu.Unlock()
			return conn, nil
		}
	} else if opts.DialAddr != "" {
		dialer.NetDialContext = func(dialCtx context.Context, _ string, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 15 * time.Second, KeepAlive: 30 * time.Second}).DialContext(dialCtx, "tcp", dialTarget)
		}
	}

	originHost := StripDefaultPort(hostHeader, httpScheme)
	headers := http.Header{
		"Host":            {hostHeader},
		"Origin":          {httpScheme + "://" + originHost},
		"Accept-Language": {"en-US,en;q=0.9"},
		"Cache-Control":   {"no-cache"},
		"Pragma":          {"no-cache"},
		"User-Agent":      {"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"},
	}

	ws, _, err := dialer.DialContext(ctx, u.String(), headers)
	if err != nil {
		return nil, fmt.Errorf("websocket dial %s: %w", u.String(), err)
	}

	ws.SetReadLimit(64 * 1024 * 1024) // 64MB max message

	stateMu.Lock()
	stateCopy := negotiatedState
	stateMu.Unlock()

	wrapped := &wsConn{
		ws:         ws,
		tlsState:   stateCopy,
		remoteAddr: ws.RemoteAddr(),
		stopCh:     make(chan struct{}),
	}
	if opts.PingInterval > 0 {
		wrapped.StartKeepAlive(opts.PingInterval)
	}
	return wrapped, nil
}
