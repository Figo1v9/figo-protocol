// Package transport provides the Layer 1 abstraction for FGXP.
// http_inject.go implements the HTTP Injection Engine used to bypass
// ISP transparent HTTP proxies or explicit carrier proxies.
package transport

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

// HTTPInjectMethod defines which injection technique to use against the
// ISP transparent proxy.
type HTTPInjectMethod string

const (
	// InjectCONNECT sends an HTTP CONNECT request. Most effective method.
	InjectCONNECT HTTPInjectMethod = "connect"

	// InjectFrontQuery sends a GET to the whitelisted host pipelined ahead of CONNECT.
	InjectFrontQuery HTTPInjectMethod = "front"

	// InjectKeepAlive sends a GET with Connection: keep-alive, then switches to stream data.
	InjectKeepAlive HTTPInjectMethod = "keepalive"
)

// HTTPInjectConfig configures the HTTP injection engine.
type HTTPInjectConfig struct {
	// WhitelistedHost is the zero-rated / allowed domain (e.g. "safaricom.com").
	WhitelistedHost string
	// TargetAddr is the destination server address for CONNECT (e.g. "1.2.3.4:443").
	TargetAddr string
	// ProxyAddr optionally specifies an explicit HTTP proxy host:port to dial.
	// When empty, ProxyPort is combined with TargetAddr's host.
	ProxyAddr string
	// ProxyPort is the default proxy port when ProxyAddr omits one (default: "80").
	ProxyPort string
	// Method is the injection technique ("connect", "front", "keepalive").
	Method HTTPInjectMethod
}

const injectBrowserUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"

// DialWithHTTPInject connects through an ISP transparent or explicit HTTP proxy
// using crafted HTTP requests with a whitelisted Host header. Returns a lossless
// buffered net.Conn over the established tunnel.
func DialWithHTTPInject(ctx context.Context, cfg *HTTPInjectConfig) (net.Conn, error) {
	if cfg == nil {
		return nil, fmt.Errorf("fgxp/transport: nil HTTPInjectConfig")
	}
	proxyPort := strings.TrimSpace(cfg.ProxyPort)
	if proxyPort == "" {
		proxyPort = "80"
	}
	method := cfg.Method
	if method == "" {
		method = InjectCONNECT
	}

	proxyAddr := strings.TrimSpace(cfg.ProxyAddr)
	if proxyAddr != "" {
		proxyAddr = EnsurePort(proxyAddr, proxyPort)
	} else if method == InjectKeepAlive && strings.TrimSpace(cfg.ProxyPort) == "" {
		proxyAddr = EnsurePort(strings.TrimSpace(cfg.TargetAddr), "80")
	} else {
		vpsHost := strings.TrimSpace(cfg.TargetAddr)
		if h, _, err := net.SplitHostPort(vpsHost); err == nil {
			vpsHost = h
		} else {
			vpsHost = strings.TrimPrefix(strings.TrimSuffix(vpsHost, "]"), "[")
		}
		proxyAddr = net.JoinHostPort(vpsHost, proxyPort)
	}

	dialer := &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}
	rawConn, err := dialer.DialContext(ctx, "tcp", proxyAddr)
	if err != nil {
		return nil, fmt.Errorf("dial transparent proxy %s: %w", proxyAddr, err)
	}

	switch method {
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

func injectCONNECT(conn net.Conn, cfg *HTTPInjectConfig) (net.Conn, error) {
	payload := fmt.Sprintf(
		"CONNECT %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Proxy-Connection: keep-alive\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n",
		cfg.TargetAddr,
		cfg.WhitelistedHost,
		injectBrowserUA,
	)

	if err := writeAllWithTimeout(conn, []byte(payload), 10*time.Second); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT injection: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := readInjectHTTPResponse(br, conn, http.MethodConnect, 15*time.Second, false)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT proxy response: %w", err)
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("proxy rejected CONNECT (status: %d %s)", resp.StatusCode, resp.Status)
	}

	return NewBufferedNetConn(conn, br), nil
}

func injectFrontQuery(conn net.Conn, cfg *HTTPInjectConfig) (net.Conn, error) {
	payload := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Connection: keep-alive\r\n"+
			"\r\n"+
			"CONNECT %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Proxy-Connection: keep-alive\r\n"+
			"\r\n",
		cfg.WhitelistedHost,
		injectBrowserUA,
		cfg.TargetAddr,
		cfg.WhitelistedHost,
	)

	if err := writeAllWithTimeout(conn, []byte(payload), 10*time.Second); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write front-query injection: %w", err)
	}

	br := bufio.NewReader(conn)

	// 1. Drain the pipelined GET / response including any body under deadline.
	getResp, err := readInjectHTTPResponse(br, conn, http.MethodGet, 15*time.Second, true)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read front-query GET response: %w", err)
	}
	if getResp.Close {
		conn.Close()
		return nil, fmt.Errorf("proxy closed connection after pipelined GET (status: %d)", getResp.StatusCode)
	}

	// 2. Read the CONNECT tunnel establishment response.
	connResp, err := readInjectHTTPResponse(br, conn, http.MethodConnect, 15*time.Second, false)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read front-query CONNECT response: %w", err)
	}
	if connResp.StatusCode != http.StatusOK && connResp.StatusCode != http.StatusSwitchingProtocols {
		conn.Close()
		return nil, fmt.Errorf("proxy rejected FRONT-QUERY CONNECT (status: %d %s)", connResp.StatusCode, connResp.Status)
	}

	return NewBufferedNetConn(conn, br), nil
}

func injectKeepAlive(conn net.Conn, cfg *HTTPInjectConfig) (net.Conn, error) {
	payload := fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: %s\r\n"+
			"Connection: keep-alive\r\n"+
			"Accept: */*\r\n"+
			"\r\n",
		cfg.WhitelistedHost,
		injectBrowserUA,
	)

	if err := writeAllWithTimeout(conn, []byte(payload), 10*time.Second); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write keep-alive injection: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := readInjectHTTPResponse(br, conn, http.MethodGet, 10*time.Second, true)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read keep-alive response: %w", err)
	}
	if resp.StatusCode >= 400 {
		conn.Close()
		return nil, fmt.Errorf("proxy rejected keep-alive GET (status: %d %s)", resp.StatusCode, resp.Status)
	}
	if resp.Close {
		conn.Close()
		return nil, fmt.Errorf("proxy closed connection on keep-alive response")
	}

	return NewBufferedNetConn(conn, br), nil
}

func writeAllWithTimeout(conn net.Conn, data []byte, timeout time.Duration) error {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	_, err := conn.Write(data)
	_ = conn.SetWriteDeadline(time.Time{})
	return err
}

func readInjectHTTPResponse(br *bufio.Reader, conn net.Conn, method string, timeout time.Duration, drainBody bool) (*http.Response, error) {
	_ = conn.SetReadDeadline(time.Now().Add(timeout))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()

	resp, err := http.ReadResponse(br, &http.Request{Method: method})
	if err != nil {
		return nil, err
	}
	if drainBody && resp.Body != nil {
		// Drain delimited body while deadline remains enforced.
		_, drainErr := io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		if drainErr != nil {
			return nil, fmt.Errorf("drain response body: %w", drainErr)
		}
	} else if resp.Body != nil {
		_ = resp.Body.Close()
	}
	return resp, nil
}
