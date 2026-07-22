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

func TestDomainFrontingRealIPIntegration(t *testing.T) {
	psk := []byte("test-psk-32bytes-domain-fronting")
	listenAddr := "127.0.0.1:18446"

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

	// 2. Client connects with decoying SNI + RealIP override
	clt, err := client.NewClient(client.ClientOptions{
		ServerAddr:    "whitelisted-sni-domain.com:443", // Decoy server addr
		RealIP:        listenAddr,                        // Real VPS / CDN target IP
		TransportType: transport.TCP,
		PSK:           psk,
		SNI:           "https://whitelisted-sni-domain.com/download?nocache=123",
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
		t.Fatalf("Client connect failed with RealIP domain fronting: %v", err)
	}

	st, err := clt.OpenStream(ctx)
	if err != nil {
		t.Fatalf("Failed to open stream: %v", err)
	}
	defer st.Close()

	payload := []byte("DOMAIN_FRONTING_REAL_IP_TEST")
	if _, err := st.Write(payload); err != nil {
		t.Fatalf("Failed to write to stream: %v", err)
	}
}
