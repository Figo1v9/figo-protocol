// Package transport provides Layer 7 HTTP Handshake Framing for FGXP.
package transport

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// SendHTTPFraming sends an L7 HTTP GET / WebSocket Upgrade request
// matching the specified transport URL (Path, Query, Host Header) over the raw/TLS connection.
func SendHTTPFraming(conn Conn, parsed *ParsedTransportURL) error {
	if parsed == nil || parsed.PathAndQuery == "" || parsed.PathAndQuery == "/" {
		// No custom framing path required; proceed directly
		return nil
	}

	reqBuf := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n"+
			"Accept: */*\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: websocket\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n",
		parsed.PathAndQuery,
		parsed.Host,
	)

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(reqBuf)); err != nil {
		return fmt.Errorf("write http framing request: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	// Read HTTP 101 or 200 response line from server
	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	respLine, err := br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("read http framing response: %w", err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	if !strings.Contains(respLine, "101") && !strings.Contains(respLine, "200") {
		return fmt.Errorf("unexpected http framing response: %s", strings.TrimSpace(respLine))
	}

	// Drain remaining response headers until \r\n\r\n
	for {
		line, err := br.ReadString('\n')
		if err != nil || strings.TrimSpace(line) == "" {
			break
		}
	}

	return nil
}

// HandleHTTPFramingServer checks if the incoming connection starts with an HTTP request (e.g. GET /... HTTP/1.1).
// If it is a legitimate FGXP HTTP Upgrade framing request, it consumes the header, writes an HTTP 101 response,
// and returns the Conn ready for FGXP framing.
// If it is a standard active probe HTTP request without Upgrade headers, it re-injects the request bytes so
// camouflage active probe defense can handle it normally.
func HandleHTTPFramingServer(conn Conn) (Conn, error) {
	br := bufio.NewReader(conn)
	peekBytes, err := br.Peek(4)
	if err != nil {
		if err == io.EOF {
			return conn, nil
		}
		return conn, nil
	}

	isHTTP := bytes.HasPrefix(peekBytes, []byte("GET ")) ||
		bytes.HasPrefix(peekBytes, []byte("POST")) ||
		bytes.HasPrefix(peekBytes, []byte("HEAD")) ||
		bytes.HasPrefix(peekBytes, []byte("CONN"))

	if !isHTTP {
		// Not HTTP framing; return buffered reader wrapped connection
		return &framedTransportConn{Conn: conn, r: br}, nil
	}

	// Read full HTTP request
	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, fmt.Errorf("parse incoming http framing request: %w", err)
	}
	_ = req.Body.Close()

	// Check if this is genuine FGXP Upgrade framing vs regular HTTP active probe
	isUpgrade := strings.EqualFold(req.Header.Get("Upgrade"), "websocket") || req.Header.Get("Sec-WebSocket-Key") != ""
	if !isUpgrade {
		// Not an FGXP framing upgrade; dump original request back to stream for camouflage handling
		var reqDump bytes.Buffer
		_ = req.Write(&reqDump)
		multiReader := bufio.NewReader(io.MultiReader(&reqDump, br))
		return &framedTransportConn{Conn: conn, r: multiReader}, nil
	}

	// Respond with 101 Switching Protocols
	respBuf := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Server: nginx/1.25.3\r\n\r\n"

	if _, err := conn.Write([]byte(respBuf)); err != nil {
		return nil, fmt.Errorf("write http framing 101 response: %w", err)
	}

	return &framedTransportConn{Conn: conn, r: br}, nil
}

// framedTransportConn adapts bufio.Reader to transport.Conn without losing ConnectionState() or TransportType().
type framedTransportConn struct {
	Conn
	r *bufio.Reader
}

func (f *framedTransportConn) Read(p []byte) (int, error) {
	return f.r.Read(p)
}
