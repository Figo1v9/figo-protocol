package transport

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
)

type recordingNetConn struct {
	net.Conn
	mu  sync.Mutex
	buf bytes.Buffer
}

func (r *recordingNetConn) Read(b []byte) (int, error) {
	n, err := r.Conn.Read(b)
	if n > 0 {
		r.mu.Lock()
		_, _ = r.buf.Write(b[:n])
		r.mu.Unlock()
	}
	return n, err
}

func (r *recordingNetConn) Recorded() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.buf.String()
}

func generateTestTLSCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	tmpl := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost", "cdn.example.com"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

func TestHTTPFramingRootPlaintextHost(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srvErrCh := make(chan error, 1)
	wireReqCh := make(chan string, 1)

	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			srvErrCh <- err
			return
		}
		defer rawConn.Close()

		recConn := &recordingNetConn{Conn: rawConn}
		framed, upgraded, err := HandleHTTPFramingServer(&mockTransportConn{Conn: recConn})
		wireReqCh <- recConn.Recorded()
		if err != nil {
			srvErrCh <- err
			return
		}
		if !upgraded {
			srvErrCh <- io.ErrUnexpectedEOF
			return
		}

		// Immediately write binary data after 101 Switching Protocols
		if _, err := framed.Write([]byte("HELLO_AFTER_101")); err != nil {
			srvErrCh <- err
			return
		}

		buf := make([]byte, 64)
		n, err := framed.Read(buf)
		if err != nil && err != io.EOF {
			srvErrCh <- err
			return
		}
		if string(buf[:n]) != "CLIENT_DATA" {
			srvErrCh <- io.ErrUnexpectedEOF
			return
		}
		srvErrCh <- nil
	}()

	rawClient, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawClient.Close()

	parsed, err := ParseTransportURL("http://safaricom.com")
	if err != nil {
		t.Fatalf("ParseTransportURL: %v", err)
	}
	if parsed.IsTLS || parsed.Hostname != "safaricom.com" || parsed.PathAndQuery != "/" {
		t.Fatalf("unexpected parsed URL: %+v", parsed)
	}

	framedClient, err := SendHTTPFraming(&mockTransportConn{Conn: rawClient}, parsed, "")
	if err != nil {
		t.Fatalf("SendHTTPFraming: %v", err)
	}

	respBuf := make([]byte, 32)
	n, err := framedClient.Read(respBuf)
	if err != nil {
		t.Fatalf("client read after 101: %v", err)
	}
	if string(respBuf[:n]) != "HELLO_AFTER_101" {
		t.Fatalf("got %q, want HELLO_AFTER_101", respBuf[:n])
	}

	if _, err := framedClient.Write([]byte("CLIENT_DATA")); err != nil {
		t.Fatalf("client write: %v", err)
	}

	if err := <-srvErrCh; err != nil {
		t.Fatalf("server failed: %v", err)
	}

	wireReq := <-wireReqCh
	if !strings.Contains(wireReq, "GET / HTTP/1.1\r\n") {
		t.Fatalf("expected GET / HTTP/1.1 on wire, got:\n%s", wireReq)
	}
	if !strings.Contains(wireReq, "Host: safaricom.com\r\n") {
		t.Fatalf("expected Host: safaricom.com on wire, got:\n%s", wireReq)
	}

	// Sanity check RFC 6455 key hash logic
	lines := strings.Split(wireReq, "\r\n")
	var wsKey string
	for _, line := range lines {
		if strings.HasPrefix(line, "Sec-WebSocket-Key:") {
			wsKey = strings.TrimSpace(strings.TrimPrefix(line, "Sec-WebSocket-Key:"))
		}
	}
	decodedKey, err := base64.StdEncoding.DecodeString(wsKey)
	if err != nil || len(decodedKey) != 16 {
		t.Fatalf("expected 16-byte random Sec-WebSocket-Key, got %q (err=%v)", wsKey, err)
	}
	_ = sha1.Sum([]byte(wsKey))
}

func TestHTTPInjectMethods(t *testing.T) {
	t.Run("CONNECT_coalesced", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		srvErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				srvErr <- err
				return
			}
			defer conn.Close()

			br := bufio.NewReader(conn)
			req, err := http.ReadRequest(br)
			if err != nil {
				srvErr <- err
				return
			}
			if req.Method != http.MethodConnect || req.Host != "8.8.8.8:443" {
				srvErr <- io.ErrUnexpectedEOF
				return
			}
			// Coalesce response headers with tunnel bytes
			if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\nCOALESCED_TUNNEL"); err != nil {
				srvErr <- err
				return
			}
			buf := make([]byte, 16)
			n, err := br.Read(buf)
			if err != nil && err != io.EOF {
				srvErr <- err
				return
			}
			if string(buf[:n]) != "PONG" {
				srvErr <- io.ErrUnexpectedEOF
				return
			}
			srvErr <- nil
		}()

		conn, err := DialWithHTTPInject(context.Background(), &HTTPInjectConfig{
			WhitelistedHost: "safaricom.com",
			TargetAddr:      "8.8.8.8:443",
			ProxyAddr:       ln.Addr().String(),
			Method:          InjectCONNECT,
		})
		if err != nil {
			t.Fatalf("DialWithHTTPInject: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 32)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read coalesced: %v", err)
		}
		if string(buf[:n]) != "COALESCED_TUNNEL" {
			t.Fatalf("got %q, want COALESCED_TUNNEL", buf[:n])
		}
		if _, err := conn.Write([]byte("PONG")); err != nil {
			t.Fatalf("write PONG: %v", err)
		}
		if err := <-srvErr; err != nil {
			t.Fatalf("mock proxy error: %v", err)
		}
	})

	t.Run("FrontQuery", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		srvErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				srvErr <- err
				return
			}
			defer conn.Close()

			br := bufio.NewReader(conn)
			req1, err := http.ReadRequest(br)
			if err != nil || req1.Method != http.MethodGet || req1.Host != "safaricom.com" {
				srvErr <- io.ErrUnexpectedEOF
				return
			}
			if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"); err != nil {
				srvErr <- err
				return
			}
			req2, err := http.ReadRequest(br)
			if err != nil || req2.Method != http.MethodConnect || req2.Host != "8.8.8.8:443" {
				srvErr <- io.ErrUnexpectedEOF
				return
			}
			if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
				srvErr <- err
				return
			}
			buf := make([]byte, 16)
			n, err := br.Read(buf)
			if err != nil && err != io.EOF {
				srvErr <- err
				return
			}
			_, _ = conn.Write(buf[:n])
			srvErr <- nil
		}()

		conn, err := DialWithHTTPInject(context.Background(), &HTTPInjectConfig{
			WhitelistedHost: "safaricom.com",
			TargetAddr:      "8.8.8.8:443",
			ProxyAddr:       ln.Addr().String(),
			Method:          InjectFrontQuery,
		})
		if err != nil {
			t.Fatalf("DialWithHTTPInject FrontQuery: %v", err)
		}
		defer conn.Close()

		if _, err := conn.Write([]byte("FRONT_OK")); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 16)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf[:n]) != "FRONT_OK" {
			t.Fatalf("got %q, want FRONT_OK", buf[:n])
		}
		if err := <-srvErr; err != nil {
			t.Fatalf("mock proxy error: %v", err)
		}
	})

	t.Run("KeepAlive_body_drain", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		srvErr := make(chan error, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				srvErr <- err
				return
			}
			defer conn.Close()

			br := bufio.NewReader(conn)
			req, err := http.ReadRequest(br)
			if err != nil || req.Method != http.MethodGet || req.Host != "safaricom.com" {
				srvErr <- io.ErrUnexpectedEOF
				return
			}
			if _, err := io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbodyTUNNEL_READY"); err != nil {
				srvErr <- err
				return
			}
			srvErr <- nil
		}()

		conn, err := DialWithHTTPInject(context.Background(), &HTTPInjectConfig{
			WhitelistedHost: "safaricom.com",
			TargetAddr:      ln.Addr().String(),
			Method:          InjectKeepAlive,
		})
		if err != nil {
			t.Fatalf("DialWithHTTPInject KeepAlive: %v", err)
		}
		defer conn.Close()

		buf := make([]byte, 32)
		n, err := conn.Read(buf)
		if err != nil && err != io.EOF {
			t.Fatalf("read: %v", err)
		}
		if string(buf[:n]) != "TUNNEL_READY" {
			t.Fatalf("got %q, want TUNNEL_READY (HTTP body should be drained cleanly)", buf[:n])
		}
		if err := <-srvErr; err != nil {
			t.Fatalf("server err: %v", err)
		}
	})

	t.Run("DialUTLSOverConn_CONNECT", func(t *testing.T) {
		cert := generateTestTLSCert(t)
		tlsLn, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{Certificates: []tls.Certificate{cert}})
		if err != nil {
			t.Fatalf("tls listen: %v", err)
		}
		defer tlsLn.Close()

		go func() {
			c, err := tlsLn.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()

		proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("proxy listen: %v", err)
		}
		defer proxyLn.Close()

		go func() {
			clientConn, err := proxyLn.Accept()
			if err != nil {
				return
			}
			defer clientConn.Close()

			br := bufio.NewReader(clientConn)
			req, err := http.ReadRequest(br)
			if err != nil {
				return
			}
			backendConn, err := net.Dial("tcp", req.Host)
			if err != nil {
				return
			}
			defer backendConn.Close()

			_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection established\r\n\r\n")
			go func() { _, _ = io.Copy(backendConn, br) }()
			_, _ = io.Copy(clientConn, backendConn)
		}()

		tunConn, err := DialWithHTTPInject(context.Background(), &HTTPInjectConfig{
			WhitelistedHost: "safaricom.com",
			TargetAddr:      tlsLn.Addr().String(),
			ProxyAddr:       proxyLn.Addr().String(),
			Method:          InjectCONNECT,
		})
		if err != nil {
			t.Fatalf("DialWithHTTPInject: %v", err)
		}

		tlsTun, err := DialUTLSOverConn(context.Background(), tunConn, &tls.Config{
			ServerName:         "cdn.example.com",
			InsecureSkipVerify: true,
		}, FingerprintChrome)
		if err != nil {
			tunConn.Close()
			t.Fatalf("DialUTLSOverConn: %v", err)
		}
		defer tlsTun.Close()

		if _, err := tlsTun.Write([]byte("ENCRYPTED_VIA_PROXY")); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 32)
		n, err := io.ReadFull(tlsTun, buf[:len("ENCRYPTED_VIA_PROXY")])
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf[:n]) != "ENCRYPTED_VIA_PROXY" {
			t.Fatalf("got %q, want ENCRYPTED_VIA_PROXY", buf[:n])
		}
	})
}

func TestScrambleTransportUniqueIV(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")

	// 1. Concurrent WrapConn + roundtrip on synchronous net.Pipe() must not deadlock
	cRaw, sRaw := net.Pipe()
	clientPT := &ScrambleTransport{Key: key, IsServer: false}
	serverPT := &ScrambleTransport{Key: key, IsServer: true}

	cWrapped, err := clientPT.WrapConn(&mockTransportConn{Conn: cRaw})
	if err != nil {
		t.Fatalf("client WrapConn: %v", err)
	}
	sWrapped, err := serverPT.WrapConn(&mockTransportConn{Conn: sRaw})
	if err != nil {
		t.Fatalf("server WrapConn: %v", err)
	}
	defer cWrapped.Close()
	defer sWrapped.Close()

	done := make(chan error, 1)
	go func() {
		buf := make([]byte, 12)
		if _, err := io.ReadFull(sWrapped, buf); err != nil {
			done <- err
			return
		}
		_, err := sWrapped.Write([]byte("SERVER_REPLY"))
		done <- err
	}()

	if _, err := cWrapped.Write([]byte("PIPE_NO_LOCK")); err != nil {
		t.Fatalf("client write on pipe: %v", err)
	}
	reply := make([]byte, 12)
	if _, err := io.ReadFull(cWrapped, reply); err != nil {
		t.Fatalf("client read on pipe: %v", err)
	}
	if string(reply) != "SERVER_REPLY" {
		t.Fatalf("got %q, want SERVER_REPLY", reply)
	}
	if err := <-done; err != nil {
		t.Fatalf("server pipe failed: %v", err)
	}

	// 2. Capture raw wire bytes on two separate TCP connections and verify unique IV + ciphertext
	captureWire := func(payload []byte) []byte {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		wireCh := make(chan []byte, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				wireCh <- nil
				return
			}
			defer conn.Close()
			rec := &recordingNetConn{Conn: conn}
			wrapped, err := (&ScrambleTransport{Key: key, IsServer: true}).WrapConn(&mockTransportConn{Conn: rec})
			if err != nil {
				wireCh <- nil
				return
			}
			plain := make([]byte, len(payload))
			_, _ = io.ReadFull(wrapped, plain)
			wireCh <- []byte(rec.Recorded())
		}()

		rawC, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer rawC.Close()
		wrappedC, err := (&ScrambleTransport{Key: key, IsServer: false}).WrapConn(&mockTransportConn{Conn: rawC})
		if err != nil {
			t.Fatalf("WrapConn: %v", err)
		}
		if _, err := wrappedC.Write(payload); err != nil {
			t.Fatalf("write: %v", err)
		}
		return <-wireCh
	}

	identicalPlain := bytes.Repeat([]byte("A"), 64)
	wire1 := captureWire(identicalPlain)
	wire2 := captureWire(identicalPlain)
	if len(wire1) < 16+64 || len(wire2) < 16+64 {
		t.Fatalf("short wire capture: %d / %d", len(wire1), len(wire2))
	}
	if bytes.Equal(wire1[:16], wire2[:16]) {
		t.Fatalf("expected unique 16-byte IV per connection, got identical IVs")
	}
	if bytes.Equal(wire1[16:16+64], wire2[16:16+64]) {
		t.Fatalf("expected unique ciphertext for identical plaintext, got identical ciphertexts")
	}
}

func TestIsWebSocketUpgradeRequest(t *testing.T) {
	validKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))

	validReq, _ := http.NewRequest(http.MethodGet, "https://cdn.example.com/ws", nil)
	validReq.Header.Set("Upgrade", "websocket")
	validReq.Header.Set("Connection", "keep-alive, Upgrade")
	validReq.Header.Set("Sec-WebSocket-Version", "13")
	validReq.Header.Set("Sec-WebSocket-Key", validKey)
	if !IsWebSocketUpgradeRequest(validReq) {
		t.Fatalf("expected valid upgrade request to pass")
	}

	badKeyReq := validReq.Clone(context.Background())
	badKeyReq.Header.Set("Sec-WebSocket-Key", "not-16-bytes")
	if IsWebSocketUpgradeRequest(badKeyReq) {
		t.Fatalf("expected invalid base64 key to fail")
	}

	postReq := validReq.Clone(context.Background())
	postReq.Method = http.MethodPost
	if IsWebSocketUpgradeRequest(postReq) {
		t.Fatalf("expected POST method to fail")
	}

	noConnReq := validReq.Clone(context.Background())
	noConnReq.Header.Set("Connection", "keep-alive")
	if IsWebSocketUpgradeRequest(noConnReq) {
		t.Fatalf("expected missing Upgrade token in Connection header to fail")
	}
}

func TestDialWebSocketUTLSHeadersAndALPN(t *testing.T) {
	cert := generateTestTLSCert(t)
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }}

	var capturedSNI string
	var capturedProtos []string
	var capturedHost string
	var capturedPath string
	var mu sync.Mutex

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		capturedHost = r.Host
		capturedPath = r.URL.Path
		mu.Unlock()

		wsConn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer wsConn.Close()
		mt, msg, err := wsConn.ReadMessage()
		if err != nil {
			return
		}
		_ = wsConn.WriteMessage(mt, append([]byte("ECHO:"), msg...))
	}))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"http/1.1"},
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			capturedSNI = chi.ServerName
			capturedProtos = append([]string(nil), chi.SupportedProtos...)
			mu.Unlock()
			return nil, nil
		},
	}
	srv.StartTLS()
	defer srv.Close()

	dialAddr := strings.TrimPrefix(srv.URL, "https://")
	wsConn, err := DialWebSocket(context.Background(), DialWebSocketOptions{
		WSURL:              "wss://cdn.example.com/ws-test",
		SNI:                "safaricom.com",
		HostHeader:         "cdn.example.com",
		DialAddr:           dialAddr,
		Fingerprint:        FingerprintChrome,
		InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatalf("DialWebSocket: %v", err)
	}
	defer wsConn.Close()

	if _, err := wsConn.Write([]byte("WS_DATA")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 32)
	n, err := wsConn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "ECHO:WS_DATA" {
		t.Fatalf("got %q, want ECHO:WS_DATA", buf[:n])
	}

	mu.Lock()
	defer mu.Unlock()
	if capturedSNI != "safaricom.com" {
		t.Fatalf("SNI got %q, want safaricom.com", capturedSNI)
	}
	if capturedHost != "cdn.example.com" || capturedPath != "/ws-test" {
		t.Fatalf("HTTP Host/Path got (%q, %q), want (cdn.example.com, /ws-test)", capturedHost, capturedPath)
	}
	if len(capturedProtos) != 1 || capturedProtos[0] != "http/1.1" {
		t.Fatalf("expected uTLS HTTP/1.1-only ALPN offer, got %v", capturedProtos)
	}
}

func TestSendHTTPFramingRejectsNon101AndSupportsTLSOverride(t *testing.T) {
	t.Run("rejects_200_response", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		go func() {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			_, _ = http.ReadRequest(bufio.NewReader(conn))
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
		}()

		rawC, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer rawC.Close()

		parsed, _ := ParseTransportURL("http://safaricom.com/")
		if _, err := SendHTTPFraming(&mockTransportConn{Conn: rawC}, parsed, ""); err == nil {
			t.Fatalf("expected error on HTTP 200 response (non-101)")
		}
	})

	t.Run("tls_with_hostOverride", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("listen: %v", err)
		}
		defer ln.Close()

		wireCh := make(chan string, 1)
		go func() {
			conn, err := ln.Accept()
			if err != nil {
				wireCh <- ""
				return
			}
			defer conn.Close()
			rec := &recordingNetConn{Conn: conn}
			_, upgraded, err := HandleHTTPFramingServer(&mockTransportConn{Conn: rec})
			wireCh <- rec.Recorded()
			if err != nil || !upgraded {
				return
			}
		}()

		rawC, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		defer rawC.Close()

		parsed, _ := ParseTransportURL("https://origin.example.com/")
		if _, err := SendHTTPFraming(&mockTransportConn{Conn: rawC}, parsed, "safaricom.com:443"); err != nil {
			t.Fatalf("SendHTTPFraming TLS hostOverride: %v", err)
		}

		wire := <-wireCh
		if !strings.Contains(wire, "Host: safaricom.com\r\n") {
			t.Fatalf("expected normalized Host: safaricom.com on wire, got:\n%s", wire)
		}
	})
}

func TestHandleHTTPFramingServerPreservesNonUpgradePOSTBody(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	done := make(chan error, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		framed, upgraded, err := HandleHTTPFramingServer(&mockTransportConn{Conn: conn})
		if err != nil {
			done <- err
			return
		}
		if upgraded {
			done <- io.ErrUnexpectedEOF
			return
		}

		// Simulate legacy handleCamouflage reading buffered POST request + body
		req, err := http.ReadRequest(bufio.NewReader(framed))
		if err != nil {
			done <- err
			return
		}
		defer req.Body.Close()
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			done <- err
			return
		}
		if req.Method != http.MethodPost || string(bodyBytes) != "hello=world" {
			done <- io.ErrUnexpectedEOF
			return
		}
		done <- nil
	}()

	rawC, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer rawC.Close()

	_, _ = io.WriteString(rawC, "POST /submit HTTP/1.1\r\nHost: example.com\r\nContent-Length: 11\r\n\r\nhello=world")
	if err := <-done; err != nil {
		t.Fatalf("POST fallback body preservation failed: %v", err)
	}
}


