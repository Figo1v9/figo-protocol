package transport

import (
	"crypto/tls"
	"io"
	"net"
	"testing"
)

type mockTransportConn struct {
	net.Conn
}

func (m *mockTransportConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{}
}

func (m *mockTransportConn) TransportType() Type {
	return TCP
}

func TestHTTPFramingEndToEnd(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	srvErrCh := make(chan error, 1)
	go func() {
		rawConn, err := ln.Accept()
		if err != nil {
			srvErrCh <- err
			return
		}
		defer rawConn.Close()

		tConn := &mockTransportConn{Conn: rawConn}
		framedConn, err := HandleHTTPFramingServer(tConn)
		if err != nil {
			srvErrCh <- err
			return
		}

		// Echo back data after HTTP framing
		buf := make([]byte, 64)
		n, err := framedConn.Read(buf)
		if err != nil && err != io.EOF {
			srvErrCh <- err
			return
		}
		_, _ = framedConn.Write(buf[:n])
		srvErrCh <- nil
	}()

	clientRawConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("failed to dial: %v", err)
	}
	defer clientRawConn.Close()

	clientConn := &mockTransportConn{Conn: clientRawConn}

	parsedURL, err := ParseTransportURL("https://speedtest8.example.com:8080/download?nocache=e67ec7c5&size=25000000")
	if err != nil {
		t.Fatalf("ParseTransportURL failed: %v", err)
	}

	if err := SendHTTPFraming(clientConn, parsedURL); err != nil {
		t.Fatalf("SendHTTPFraming failed: %v", err)
	}

	testPayload := []byte("FGXP_ENCRYPTED_STREAM_TEST")
	if _, err := clientConn.Write(testPayload); err != nil {
		t.Fatalf("client write error: %v", err)
	}

	respBuf := make([]byte, 64)
	n, err := clientConn.Read(respBuf)
	if err != nil {
		t.Fatalf("client read error: %v", err)
	}

	if string(respBuf[:n]) != string(testPayload) {
		t.Errorf("got %q, want %q", respBuf[:n], testPayload)
	}

	if srvErr := <-srvErrCh; srvErr != nil {
		t.Fatalf("server error: %v", srvErr)
	}
}
