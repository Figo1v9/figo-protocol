package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/figox/figox-protocol/pkg/client"
	"github.com/figox/figox-protocol/pkg/config"
	"github.com/figox/figox-protocol/pkg/server"
	"github.com/figox/figox-protocol/pkg/stream"
	"github.com/figox/figox-protocol/pkg/transport"
)

// generateSelfSignedCert generates in-memory self-signed certificate and private key.
func generateSelfSignedCert(t *testing.T) (tls.Certificate, []byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate private key: %v", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(365 * 24 * time.Hour)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		t.Fatalf("failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"FigoX Labs"},
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}

	certPemBuf := new(bytes.Buffer)
	_ = pem.Encode(certPemBuf, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal private key: %v", err)
	}
	keyPemBuf := new(bytes.Buffer)
	_ = pem.Encode(keyPemBuf, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	cert, err := tls.X509KeyPair(certPemBuf.Bytes(), keyPemBuf.Bytes())
	if err != nil {
		t.Fatalf("failed to load x509 key pair: %v", err)
	}

	return cert, certPemBuf.Bytes(), keyPemBuf.Bytes()
}

func TestFGXPEndToEndTCP(t *testing.T) {
	_, certPem, keyPem := generateSelfSignedCert(t)

	// Write cert and key to temp files since server/client loaders expect file paths.
	tempDir := t.TempDir()
	certPath := tempDir + "/cert.pem"
	keyPath := tempDir + "/key.pem"

	if err := os.WriteFile(certPath, certPem, 0600); err != nil {
		t.Fatalf("failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		t.Fatalf("failed to write key file: %v", err)
	}

	psk := []byte("very-secure-pre-shared-key-32bytes")

	// Create server options
	srvOpts := server.ServerOptions{
		ListenAddr:    "127.0.0.1:0", // Bind to free port
		TransportType: transport.TCP,
		TLSCertFile:   certPath,
		TLSKeyFile:    keyPath,
		PSK:           psk,
		Config:        config.DefaultConfig(),
	}

	srvOpts.Config.Stealth.Camouflage.Mode = "static"
	srvOpts.Config.Stealth.Timing.Enabled = false // disable timing jitter for deterministic tests
	srvOpts.Config.Stealth.Padding.Enabled = false // disable padding for testing

	srv, err := server.NewServer(srvOpts)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Close()

	// Define stream handler on server
	receivedData := make(chan []byte, 1)
	srv.OnStream(func(st *stream.Stream) {
		defer st.Close()
		buf := make([]byte, 1024)
		n, err := st.Read(buf)
		if err != nil && err != io.EOF {
			return
		}
		receivedData <- buf[:n]

		// Echo back
		_, _ = st.Write([]byte("ECHO: " + string(buf[:n])))
	})

	// Start server in background
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		_ = srv.ListenAndServe(ctx)
	}()

	// Wait for server listener to be initialized
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

	// 1. Test standard authenticated FGXP client
	t.Run("FGXP client communication", func(t *testing.T) {
		cltOpts := client.ClientOptions{
			ServerAddr:    serverAddr,
			TransportType: transport.TCP,
			PSK:           psk,
			SNI:           "localhost",
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true, // skip self-signed cert check
			},
		}

		clt, err := client.NewClient(cltOpts)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer clt.Close()

		if err := clt.Connect(ctx); err != nil {
			t.Fatalf("client connection/auth failed: %v", err)
		}

		st, err := clt.OpenStream(ctx)
		if err != nil {
			t.Fatalf("failed to open stream: %v", err)
		}
		defer st.Close()

		testMsg := []byte("Hello, FGXP!")
		_, err = st.Write(testMsg)
		if err != nil {
			t.Fatalf("failed to write to stream: %v", err)
		}

		// Verify server received correct data
		select {
		case recv := <-receivedData:
			if !bytes.Equal(recv, testMsg) {
				t.Errorf("server received %q, want %q", recv, testMsg)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for server to receive stream data")
		}

		// Read echo from server
		echoBuf := make([]byte, 1024)
		n, err := st.Read(echoBuf)
		if err != nil {
			t.Fatalf("failed to read echo: %v", err)
		}
		expectedEcho := "ECHO: " + string(testMsg)
		if string(echoBuf[:n]) != expectedEcho {
			t.Errorf("client got echo %q, want %q", echoBuf[:n], expectedEcho)
		}
	})

	// 2. Test active probe resistance (sending HTTP prober request)
	t.Run("Active probe camouflage fallback", func(t *testing.T) {
		// Create a standard HTTP client that ignores certificate issues
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
			Timeout: 2 * time.Second,
		}

		resp, err := httpClient.Get(fmt.Sprintf("https://%s/", serverAddr))
		if err != nil {
			t.Fatalf("failed to probe server with HTTPS request: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("probe status code = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read probe body: %v", err)
		}

		if !bytes.Contains(body, []byte("Welcome to nginx!")) {
			t.Errorf("probe body did not contain nginx camouflage page: %q", body)
		}

		serverHeader := resp.Header.Get("Server")
		if serverHeader != "nginx/1.25.3" {
			t.Errorf("probe server header = %q, want %q", serverHeader, "nginx/1.25.3")
		}
	})
}

func TestSNIBugHostBypass(t *testing.T) {
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

	psk := []byte("very-secure-pre-shared-key-32bytes")

	srvOpts := server.ServerOptions{
		ListenAddr:    "127.0.0.1:0",
		TransportType: transport.TCP,
		TLSCertFile:   certPath,
		TLSKeyFile:    keyPath,
		PSK:           psk,
		Config:        config.DefaultConfig(),
	}

	srvOpts.Config.Stealth.Camouflage.Mode = "static"
	srvOpts.Config.Stealth.Timing.Enabled = false
	srvOpts.Config.Stealth.Padding.Enabled = false

	srv, err := server.NewServer(srvOpts)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	defer srv.Close()

	// Define stream handler on server
	receivedData := make(chan []byte, 1)
	srv.OnStream(func(st *stream.Stream) {
		defer st.Close()
		buf := make([]byte, 1024)
		n, err := st.Read(buf)
		if err != nil && err != io.EOF {
			return
		}
		receivedData <- buf[:n]
		_, _ = st.Write([]byte("ECHO: " + string(buf[:n])))
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
		t.Fatalf("server failed to start and bind to a port in time")
	}

	// Case 1: Connect using a completely spoofed SNI (SNI Bug Host) with InsecureSkipVerify
	t.Run("FGXP Client connection with fake SNI", func(t *testing.T) {
		cltOpts := client.ClientOptions{
			ServerAddr:    serverAddr,
			TransportType: transport.TCP,
			PSK:           psk,
			SNI:           "whitelisted-sni-bug-host.com", // Spoofed SNI
			TLSConfig: &tls.Config{
				InsecureSkipVerify: true, // Bypass verification since server returns the default self-signed certificate
			},
		}

		clt, err := client.NewClient(cltOpts)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer clt.Close()

		if err := clt.Connect(ctx); err != nil {
			t.Fatalf("client connection with fake SNI failed: %v", err)
		}

		st, err := clt.OpenStream(ctx)
		if err != nil {
			t.Fatalf("failed to open stream: %v", err)
		}
		defer st.Close()

		testMsg := []byte("Testing SNI Bug Host bypass")
		_, err = st.Write(testMsg)
		if err != nil {
			t.Fatalf("failed to write to stream: %v", err)
		}

		select {
		case recv := <-receivedData:
			if !bytes.Equal(recv, testMsg) {
				t.Errorf("server received %q, want %q", recv, testMsg)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timeout waiting for server to receive stream data under fake SNI")
		}
	})

	// Case 2: Verification of TLS standard behavior when InsecureSkipVerify is FALSE (Should FAIL due to host verification)
	t.Run("Client connection with fake SNI and verification enabled (Should Fail)", func(t *testing.T) {
		cltOpts := client.ClientOptions{
			ServerAddr:    serverAddr,
			TransportType: transport.TCP,
			PSK:           psk,
			SNI:           "whitelisted-sni-bug-host.com",
			TLSConfig: &tls.Config{
				InsecureSkipVerify: false, // TLS should reject because cert is self-signed/doesn't match SNI
			},
		}

		clt, err := client.NewClient(cltOpts)
		if err != nil {
			t.Fatalf("failed to create client: %v", err)
		}
		defer clt.Close()

		err = clt.Connect(ctx)
		if err == nil {
			t.Fatal("expected connection to fail due to TLS verification mismatch, but it succeeded")
		}
		t.Logf("Successfully rejected mismatched SNI without skip-verify: %v", err)
	})

	// Case 3: Camouflage behavior for unauthenticated probers attempting to use the fake SNI
	t.Run("HTTP Probe with fake SNI camouflage response", func(t *testing.T) {
		httpClient := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
					ServerName:         "whitelisted-sni-bug-host.com", // probe using fake SNI
				},
			},
			Timeout: 2 * time.Second,
		}

		resp, err := httpClient.Get(fmt.Sprintf("https://%s/some-censored-path", serverAddr))
		if err != nil {
			t.Fatalf("failed to probe with fake SNI: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Errorf("status code = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read body: %v", err)
		}

		if !bytes.Contains(body, []byte("Welcome to nginx!")) {
			t.Errorf("body did not contain nginx template: %q", body)
		}
	})
}

