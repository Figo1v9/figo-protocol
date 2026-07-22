package integration

import (
	"context"
	"crypto/tls"
	"testing"
	"time"

	"github.com/figox/figox-protocol/pkg/client"
	"github.com/figox/figox-protocol/pkg/server"
	"github.com/figox/figox-protocol/pkg/transport"
)

func TestFullURLTransportFramingIntegration(t *testing.T) {
	psk := []byte("test-psk-32bytes-secret-key-1234")
	listenAddr := "127.0.0.1:18444"

	// 1. Start Server
	srv, err := server.NewServer(server.ServerOptions{
		ListenAddr:    listenAddr,
		TransportType: transport.TCP,
		TLSCertFile:   "../../cert.pem",
		TLSKeyFile:    "../../key.pem",
		PSK:           psk,
	})
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		_ = srv.ListenAndServe(context.Background())
	}()
	defer srv.Close()

	time.Sleep(200 * time.Millisecond)

	// 2. Start Client with Full Transport URL in SNI
	fullURL := "https://speedtest8.example.com:8080/download?nocache=e67ec7c5-6f5d-4c13-9eb7-ffc67df76bc4&size=25000000&guid=bee7c502-064a-4ae5-bb33-e35fc1de8f1e"

	clt, err := client.NewClient(client.ClientOptions{
		ServerAddr:    listenAddr,
		TransportType: transport.TCP,
		PSK:           psk,
		SNI:           fullURL,
		Fingerprint:   "chrome",
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer clt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := clt.Connect(ctx); err != nil {
		t.Fatalf("Client connect failed: %v", err)
	}

	st, err := clt.OpenStream(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}
	defer st.Close()

	payload := []byte("PING_FULL_URL_TEST")
	if _, err := st.Write(payload); err != nil {
		t.Fatalf("Failed to write to stream: %v", err)
	}
}
