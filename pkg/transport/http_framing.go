// Package transport provides Layer 7 HTTP Handshake Framing for FGXP.
package transport

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/figox/figox-protocol/pkg/stealth"
)

const wsGUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

func generateWebSocketKey() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

func computeWebSocketAccept(key string) string {
	sum := sha1.Sum([]byte(strings.TrimSpace(key) + wsGUID))
	return base64.StdEncoding.EncodeToString(sum[:])
}

func isHTTPMethodPrefix(peek []byte) bool {
	verbs := []string{"GET ", "POST", "HEAD", "PUT ", "DELE", "OPTI", "PATC", "CONN", "TRAC"}
	for _, v := range verbs {
		if len(peek) >= len(v) && string(peek[:len(v)]) == v {
			return true
		}
	}
	return false
}

// SendHTTPFraming sends an L7 HTTP GET / Upgrade request matching the parsed
// transport URL or explicit Host header override. Returns a lossless Conn
// wrapper retaining any buffered unread bytes from the HTTP response reader.
func SendHTTPFraming(conn Conn, parsed *ParsedTransportURL, hostOverride string) (Conn, error) {
	hostOverride = strings.TrimSpace(hostOverride)
	if parsed == nil && hostOverride == "" {
		return conn, nil
	}

	// Over TLS without an explicit custom path or explicit Host override, no extra
	// inner HTTP upgrade framing is needed. Over plaintext TCP (!IsTLS), always
	// emit the HTTP request so Host headers (e.g. http://safaricom.com) appear
	// on the wire even on "/".
	if hostOverride == "" && parsed != nil && parsed.IsTLS && (parsed.PathAndQuery == "" || parsed.PathAndQuery == "/") {
		return conn, nil
	}

	pathAndQuery := "/"
	if parsed != nil && parsed.PathAndQuery != "" {
		pathAndQuery = parsed.PathAndQuery
	}
	hostHeader := NormalizeHTTPHost(parsed, hostOverride)
	if hostHeader == "" {
		hostHeader = "localhost"
	}

	wsKey, err := generateWebSocketKey()
	if err != nil {
		return nil, fmt.Errorf("generate websocket key: %w", err)
	}

	reqBuf := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n"+
			"Accept: */*\r\n"+
			"Connection: Upgrade\r\n"+
			"Upgrade: websocket\r\n"+
			"Sec-WebSocket-Version: 13\r\n"+
			"Sec-WebSocket-Key: %s\r\n\r\n",
		pathAndQuery,
		hostHeader,
		wsKey,
	)

	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(reqBuf)); err != nil {
		return nil, fmt.Errorf("write http framing request: %w", err)
	}
	_ = conn.SetWriteDeadline(time.Time{})

	br := bufio.NewReader(conn)
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodGet})
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("read http framing response: %w", err)
	}
	_ = resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		return nil, fmt.Errorf("unexpected http framing response: %d %s", resp.StatusCode, resp.Status)
	}

	return NewBufferedConn(conn, br), nil
}

// HandleHTTPFramingServer inspects the incoming legacy connection for an HTTP
// Upgrade framing request. Returns (wrappedConn, true, nil) if an HTTP 101
// upgrade succeeded, or (wrappedConn, false, nil) preserving the full request
// bytes for camouflage fallback if not an FGXP upgrade.
func HandleHTTPFramingServer(conn Conn) (Conn, bool, error) {
	br := bufio.NewReader(conn)
	peekBytes, err := br.Peek(4)
	if err != nil {
		return NewBufferedConn(conn, br), false, nil
	}

	if !isHTTPMethodPrefix(peekBytes) {
		return NewBufferedConn(conn, br), false, nil
	}

	req, err := http.ReadRequest(br)
	if err != nil {
		return nil, false, fmt.Errorf("parse incoming http framing request: %w", err)
	}

	wsKey := strings.TrimSpace(req.Header.Get("Sec-WebSocket-Key"))
	isUpgrade := req.Method == http.MethodGet &&
		strings.EqualFold(req.Header.Get("Upgrade"), "websocket") &&
		wsKey != ""

	if !isUpgrade {
		var reqDump bytes.Buffer
		_ = req.Write(&reqDump)
		_ = req.Body.Close()
		multiReader := bufio.NewReader(io.MultiReader(&reqDump, br))
		return NewBufferedConn(conn, multiReader), false, nil
	}
	_ = req.Body.Close()

	accept := computeWebSocketAccept(wsKey)
	respBuf := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: " + accept + "\r\n" +
		"Server: " + stealth.DefaultServerHeader + "\r\n\r\n"

	if _, err := conn.Write([]byte(respBuf)); err != nil {
		return nil, false, fmt.Errorf("write http framing 101 response: %w", err)
	}

	return NewBufferedConn(conn, br), true, nil
}
