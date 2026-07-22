package integration

import (
	"context"
	"testing"
	"time"

	"github.com/figox/figox-protocol/pkg/client"
	"github.com/figox/figox-protocol/pkg/server"
	"github.com/figox/figox-protocol/pkg/transport"
)

func TestPlaintextHTTPFramingIntegration(t *testing.T) {
	psk := []byte("test-psk-32bytes-plaintext-http")
	listenAddr := "127.0.0.1:18447"

	// 1. Start Server without TLS certificates (Raw TCP HTTP framing mode)
	srv, err := server.NewServer(server.ServerOptions{
		ListenAddr:    listenAddr,
		TransportType: transport.TCP,
		NoTLS:         true,
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

	// 2. Client connects using plaintext HTTP scheme (http://digital.gov.eg/)
	clt, err := client.NewClient(client.ClientOptions{
		ServerAddr:    listenAddr,
		TransportType: transport.TCP,
		PSK:           psk,
		SNI:           "http://digital.gov.eg/",
	})
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}
	defer clt.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := clt.Connect(ctx); err != nil {
		t.Fatalf("Client connect failed in Plaintext HTTP Framing mode: %v", err)
	}

	st, err := clt.OpenStream(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}
	defer st.Close()

	payload := []byte("PLAINTEXT_HTTP_FRAMING_TEST")
	if _, err := st.Write(payload); err != nil {
		t.Fatalf("Failed to write to stream: %v", err)
	}
}
