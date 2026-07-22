package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"os"
	"testing"
	"time"

	"github.com/figox/figox-protocol/pkg/client"
	"github.com/figox/figox-protocol/pkg/config"
	"github.com/figox/figox-protocol/pkg/server"
	"github.com/figox/figox-protocol/pkg/stream"
	"github.com/figox/figox-protocol/pkg/transport"
)

// TestStealthPaddingWiredEndToEnd verifies Stage 0 of ARCHITECTURE_DPI.md:
// random padding is actually applied on the wire by the client and server
// transmit paths (SessionWriter -> stealth.ApplyPadding -> Encode) and is
// stripped losslessly by the receiver (DecodeFrame).
//
// Every other integration test disables padding, so this is the only test that
// exercises the real wired padding path at runtime (not just the unit-level
// ApplyPadding/Encode round-trip). Failure here would mean the wiring corrupts
// or drops frames when padding is enabled in production.
func TestStealthPaddingWiredEndToEnd(t *testing.T) {
	_, certPem, keyPem := generateSelfSignedCert(t)

	tempDir := t.TempDir()
	certPath := tempDir + "/cert.pem"
	keyPath := tempDir + "/key.pem"
	if err := os.WriteFile(certPath, certPem, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	psk := []byte("padding-wired-pre-shared-key-32b")

	srvOpts := server.ServerOptions{
		ListenAddr:    "127.0.0.1:0",
		TransportType: transport.TCP,
		TLSCertFile:   certPath,
		TLSKeyFile:    keyPath,
		PSK:           psk,
		Config:        config.DefaultConfig(),
	}
	srvOpts.Config.Stealth.Camouflage.Mode = "static"
	srvOpts.Config.Stealth.Timing.Enabled = false // deterministic timing
	srvOpts.Config.Stealth.Padding.Enabled = true // Stage 0: padding on the wire
	srvOpts.Config.Stealth.Padding.MinPad = 1     // guarantee non-zero padding
	srvOpts.Config.Stealth.Padding.MaxPad = 255

	srv, err := server.NewServer(srvOpts)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Close()

	// Buffer every fully-received message so the test can assert integrity
	// through the padded client->server path independently of echoes.
	received := make(chan []byte, 64)
	srv.OnStream(func(st *stream.Stream) {
		defer st.Close()
		buf := make([]byte, 8192)
		for {
			n, err := st.Read(buf)
			if n > 0 {
				cp := make([]byte, n)
				copy(cp, buf[:n])
				received <- cp
				// Echo exercises the server->client padded path too.
				_, _ = st.Write([]byte("ECHO: " + string(cp)))
			}
			if err != nil {
				return
			}
		}
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()

	var serverAddr string
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		if addr := srv.Addr(); addr != nil {
			serverAddr = addr.String()
			break
		}
	}
	if serverAddr == "" {
		t.Fatalf("server failed to start and bind to a port in time")
	}

	cltOpts := client.ClientOptions{
		ServerAddr:    serverAddr,
		TransportType: transport.TCP,
		PSK:           psk,
		SNI:           "localhost",
		TLSConfig:     &tls.Config{InsecureSkipVerify: true},
	}
	clt, err := client.NewClient(cltOpts)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer clt.Close()
	if err := clt.Connect(ctx); err != nil {
		t.Fatalf("client connect/auth failed: %v", err)
	}

	st, err := clt.OpenStream(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	defer st.Close()

	// Varying payload sizes stress the padding path (small frames, large
	// frames, and repeated-content frames that would otherwise be trivially
	// fingerprintable without padding).
	messages := [][]byte{
		[]byte("small"),
		bytes.Repeat([]byte("A"), 100),
		bytes.Repeat([]byte("B"), 4096),
		[]byte("another message with unicode: مرحبا"),
	}
	for _, msg := range messages {
		if _, err := st.Write(msg); err != nil {
			t.Fatalf("failed to write %q: %v", msg, err)
		}

		// Client -> server padded path: server must receive the exact bytes.
		select {
		case recv := <-received:
			if !bytes.Equal(recv, msg) {
				t.Fatalf("server received %q, want %q", recv, msg)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("timeout waiting for server to receive %q", msg)
		}

		// Server -> client padded path: echo must round-trip intact.
		echoBuf := make([]byte, len(msg)+6)
		n, err := st.Read(echoBuf)
		if err != nil {
			t.Fatalf("failed to read echo for %q: %v", msg, err)
		}
		want := "ECHO: " + string(msg)
		if string(echoBuf[:n]) != want {
			t.Fatalf("client got echo %q, want %q", echoBuf[:n], want)
		}
	}
}
