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

func TestStage5AndStage6EndToEnd(t *testing.T) {
	_, certPem, keyPem := generateSelfSignedCert(t)

	tempDir := t.TempDir()
	certPath := tempDir + "/cert.pem"
	keyPath := tempDir + "/key.pem"

	if err := os.WriteFile(certPath, certPem, 0600); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}

	psk := []byte("stage5-stage6-e2e-psk-32b-key!")
	ptSecret := "stage5-scramble-secret-key-32b!"

	srvCfg := config.DefaultConfig()
	srvCfg.Stealth.Pluggable.Enabled = true
	srvCfg.Stealth.Pluggable.Name = "scramble"
	srvCfg.Stealth.Pluggable.Secret = ptSecret

	srvCfg.Stealth.Padding.Enabled = true
	srvCfg.Stealth.Padding.Mode = "adaptive"

	srvOpts := server.ServerOptions{
		ListenAddr:    "127.0.0.1:0",
		TransportType: transport.TCP,
		TLSCertFile:   certPath,
		TLSKeyFile:    keyPath,
		PSK:           psk,
		Config:        srvCfg,
	}

	srv, err := server.NewServer(srvOpts)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Close()

	srv.OnStream(func(st *stream.Stream) {
		defer st.Close()
		buf := make([]byte, 1024)
		n, err := st.Read(buf)
		if err != nil {
			return
		}
		_, _ = st.Write(buf[:n])
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.ListenAndServe(ctx)
	}()

	var serverAddr string
	for i := 0; i < 20; i++ {
		time.Sleep(50 * time.Millisecond)
		if addr := srv.Addr(); addr != nil {
			serverAddr = addr.String()
			break
		}
	}

	if serverAddr == "" {
		t.Fatalf("server failed to start")
	}

	cltCfg := &config.ClientConfig{
		Stealth: config.StealthSection{
			Padding: config.PaddingSection{
				Enabled: true,
				Mode:    "adaptive",
				MinPad:  0,
				MaxPad:  255,
			},
			Timing: config.TimingSection{
				Enabled:  true,
				JitterMS: 10,
			},
			Pluggable: config.PluggableSection{
				Enabled: true,
				Name:    "scramble",
				Secret:  ptSecret,
			},
		},
		Streams: config.StreamsSection{
			InitialWindow: 65536,
		},
	}

	cltOpts := client.ClientOptions{
		ServerAddr:    serverAddr,
		TransportType: transport.TCP,
		PSK:           psk,
		SNI:           "localhost",
		TLSConfig:     &tls.Config{InsecureSkipVerify: true},
		Config:        cltCfg,
	}

	clt, err := client.NewClient(cltOpts)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	defer clt.Close()

	if err := clt.Connect(ctx); err != nil {
		t.Fatalf("failed to connect: %v", err)
	}

	st, err := clt.OpenStream(ctx)
	if err != nil {
		t.Fatalf("failed to open stream: %v", err)
	}
	defer st.Close()

	testData := []byte("Hello, FGXP Stage 5 (Pluggable Transport) and Stage 6 (Adaptive Shaping)!")
	if _, err := st.Write(testData); err != nil {
		t.Fatalf("failed to write to stream: %v", err)
	}

	buf := make([]byte, len(testData))
	if _, err := st.Read(buf); err != nil {
		t.Fatalf("failed to read from stream: %v", err)
	}

	if !bytes.Equal(testData, buf) {
		t.Errorf("data mismatch! Expected %q, got %q", testData, buf)
	}
}
