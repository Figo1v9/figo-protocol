// Package transport provides the Layer 1 abstraction for FGXP.
// http_inject.go implements the HTTP Injection Engine used to bypass
// ISP transparent HTTP proxies on zero-balance mobile data networks.
//
// Technique: The ISP runs a transparent proxy on port 80 that intercepts
// all TCP connections. It checks the Host header against a whitelist of
// free-access domains (e.g. digital.gov.eg). By sending an HTTP CONNECT
// request with the whitelisted Host header, we trick the proxy into
// establishing an opaque TCP tunnel to our VPS server. Once the tunnel
// is open, the proxy stops inspecting the data and all FGXP frames flow
// through undetected.
//
// This is the exact technique used by HTTP Custom, HA Tunnel, Your Freedom,
// and other zero-balance bypass tools worldwide.
package transport

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// HTTPInjectMethod defines which injection technique to use against the
// ISP transparent proxy.
type HTTPInjectMethod string

const (
	// InjectCONNECT sends an HTTP CONNECT request. The proxy creates an
	// opaque TCP tunnel and stops inspecting data. Most effective method.
	InjectCONNECT HTTPInjectMethod = "connect"

	// InjectFrontQuery sends a legitimate GET to the whitelisted host,
	// immediately followed by a CONNECT to the VPS. Exploits proxy
	// request pipelining.
	InjectFrontQuery HTTPInjectMethod = "front"

	// InjectKeepAlive sends a GET with Connection: keep-alive, then
	// switches the stream to binary FGXP frames on the same connection.
	InjectKeepAlive HTTPInjectMethod = "keepalive"
)

// HTTPInjectConfig configures the HTTP injection engine.
type HTTPInjectConfig struct {
	// WhitelistedHost is the domain the ISP allows for free (e.g. "digital.gov.eg")
	WhitelistedHost string
	// TargetAddr is the actual VPS address to tunnel to (e.g. "34.139.64.35:443")
	TargetAddr string
	// ProxyPort is the port the transparent proxy intercepts (usually 80)
	ProxyPort string
	// Method is the injection technique to use
	Method HTTPInjectMethod
}

// DialWithHTTPInject connects through an ISP transparent HTTP proxy by
// sending crafted HTTP requests with whitelisted Host headers. Returns a
// raw net.Conn that tunnels through the proxy to the target VPS.
func DialWithHTTPInject(ctx context.Context, cfg *HTTPInjectConfig) (net.Conn, error) {
	if cfg.ProxyPort == "" {
		cfg.ProxyPort = "80"
	}
	if cfg.Method == "" {
		cfg.Method = InjectCONNECT
	}

	// Extract VPS IP from target address for dialing port 80
	vpsHost, _, err := net.SplitHostPort(cfg.TargetAddr)
	if err != nil {
		vpsHost = cfg.TargetAddr
	}
	proxyAddr := net.JoinHostPort(vpsHost, cfg.ProxyPort)

	dialer := &net.Dialer{
		KeepAlive: 30 * time.Second,
	}
	rawConn, err := dialer.DialContext(ctx, "tcp4", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial transparent proxy %s: %w", proxyAddr, err)
	}

	switch cfg.Method {
	case InjectCONNECT:
		return injectCONNECT(rawConn, cfg)
	case InjectFrontQuery:
		return injectFrontQuery(rawConn, cfg)
	case InjectKeepAlive:
		return injectKeepAlive(rawConn, cfg)
	default:
		return injectCONNECT(rawConn, cfg)
	}
}

// injectCONNECT sends an HTTP CONNECT request through the ISP transparent proxy.
// The proxy sees Host: whitelisted_host and creates an opaque tunnel.
func injectCONNECT(conn net.Conn, cfg *HTTPInjectConfig) (net.Conn, error) {
	payload := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n"+
			"Proxy-Connection: keep-alive\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n",
		cfg.TargetAddr,
		cfg.WhitelistedHost,
	)

	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT injection: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	// Read proxy response
	return readProxyResponse(conn, "CONNECT")
}

// injectFrontQuery sends a GET to the whitelisted host first, then a CONNECT.
// Exploits HTTP pipelining in the transparent proxy.
func injectFrontQuery(conn net.Conn, cfg *HTTPInjectConfig) (net.Conn, error) {
	payload := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"CONNECT %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Proxy-Connection: keep-alive\r\n"+
			"\r\n",
		cfg.WhitelistedHost,
		cfg.TargetAddr,
		cfg.WhitelistedHost,
	)

	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write front-query injection: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	// Read and discard the first GET response, then read the CONNECT response
	return readProxyResponse(conn, "FRONT-QUERY")
}

// injectKeepAlive sends a GET request with Connection: keep-alive, then
// immediately streams binary data on the same kept-alive connection.
func injectKeepAlive(conn net.Conn, cfg *HTTPInjectConfig) (net.Conn, error) {
	payload := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n"+
			"Connection: keep-alive\r\n"+
			"Accept: */*\r\n"+
			"\r\n",
		cfg.WhitelistedHost,
	)

	_ = conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write keep-alive injection: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	// Read and drain the GET response, then return the open connection
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	// Read status line
	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read keep-alive response: %w", err)
	}
	_ = statusLine // We don't care about the status for keep-alive mode

	// Drain all headers
	for {
		line, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Connection is now kept alive and ready for binary FGXP frames
	return conn, nil
}

// readProxyResponse reads the transparent proxy's response after a CONNECT
// or front-query injection. Expects a 200 response indicating tunnel established.
func readProxyResponse(conn net.Conn, method string) (net.Conn, error) {
	_ = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	br := bufio.NewReader(conn)

	statusLine, err := br.ReadString('\n')
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read %s proxy response: %w", method, err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Accept 200 (tunnel established) or 101 (switching protocols)
	if !strings.Contains(statusLine, "200") && !strings.Contains(statusLine, "101") {
		conn.Close()
		return nil, fmt.Errorf("proxy rejected %s (response: %s)", method, strings.TrimSpace(statusLine))
	}

	// Drain remaining response headers until \r\n\r\n
	for {
		line, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	// Tunnel is established - all subsequent data flows through opaquely
	return conn, nil
}
