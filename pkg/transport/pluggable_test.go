package transport

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"io"
	"net"
	"testing"
	"time"
)

// pipeConn wraps net.Conn to satisfy transport.Conn
type pipeConn struct {
	net.Conn
	tType Type
}

func (p *pipeConn) TransportType() Type {
	return p.tType
}

func (p *pipeConn) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{}
}

func TestScrambleTransportRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()

	tp1 := &pipeConn{Conn: c1, tType: TCP}
	tp2 := &pipeConn{Conn: c2, tType: TCP}

	scrambleKey := []byte("stage5-pluggable-transport-test!")

	stClient := &ScrambleTransport{Key: scrambleKey, IsServer: false}
	stServer := &ScrambleTransport{Key: scrambleKey, IsServer: true}

	clientConn, err := stClient.WrapConn(tp1)
	if err != nil {
		t.Fatalf("failed to wrap client conn: %v", err)
	}

	serverConn, err := stServer.WrapConn(tp2)
	if err != nil {
		t.Fatalf("failed to wrap server conn: %v", err)
	}

	defer clientConn.Close()
	defer serverConn.Close()

	payload := make([]byte, 1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatalf("failed to generate random payload: %v", err)
	}

	errCh := make(chan error, 1)
	readBuf := make([]byte, len(payload))

	go func() {
		_, err := io.ReadFull(serverConn, readBuf)
		errCh <- err
	}()

	if _, err := clientConn.Write(payload); err != nil {
		t.Fatalf("client write failed: %v", err)
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("server read failed: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for server read")
	}

	if !bytes.Equal(payload, readBuf) {
		t.Errorf("roundtrip payload mismatch!")
	}
}

func TestPluggableRegistry(t *testing.T) {
	reg := NewRegistry()

	pt, ok := reg.Get("scramble")
	if !ok || pt == nil {
		t.Fatalf("expected registered 'scramble' transport")
	}
	if pt.Name() != "scramble" {
		t.Errorf("expected transport name 'scramble', got %q", pt.Name())
	}
}
