package integration

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/figox/figox-protocol/pkg/client"
	"github.com/figox/figox-protocol/pkg/config"
	"github.com/figox/figox-protocol/pkg/protocol"
	"github.com/figox/figox-protocol/pkg/server"
	"github.com/figox/figox-protocol/pkg/stream"
	"github.com/figox/figox-protocol/pkg/transport"
)

func waitServerAddr(t *testing.T, srv *server.Server) string {
	t.Helper()
	for i := 0; i < 40; i++ {
		if addr := srv.Addr(); addr != nil {
			return addr.String()
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("server failed to bind address in time")
	return ""
}

func TestWebSocketServerClientUTLSE2E(t *testing.T) {
	_, certPem, keyPem := generateSelfSignedCert(t)
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	if err := os.WriteFile(certPath, certPem, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	psk := []byte("imperva-cdn-ws-test-key-32-bytes!")

	t.Run("WSS_uTLS_Chrome_With_Host_SNI_RealIP", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Server.Transport = "ws"
		cfg.Server.WSPath = "/ws-imperva-test"
		cfg.Server.BehindCDN = true
		cfg.Stealth.Camouflage.Mode = "static"
		cfg.Stealth.Timing.Enabled = false
		cfg.Stealth.Padding.Enabled = false

		srv, err := server.NewServer(server.ServerOptions{
			ListenAddr:    "127.0.0.1:0",
			TransportType: transport.TCP,
			TLSCertFile:   certPath,
			TLSKeyFile:    keyPath,
			PSK:           psk,
			Config:        cfg,
		})
		if err != nil {
			t.Fatalf("NewServer: %v", err)
		}
		defer srv.Close()

		srv.OnStream(func(st *stream.Stream) {
			defer st.Close()
			buf := make([]byte, 256)
			for {
				n, err := st.Read(buf)
				if n > 0 {
					_, _ = st.Write([]byte("ECHO:" + string(buf[:n])))
				}
				if err != nil {
					return
				}
			}
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = srv.ListenAndServe(ctx) }()
		serverAddr := waitServerAddr(t, srv)

		insecureTrue := true
		clt, err := client.NewClient(client.ClientOptions{
			WSURL:              "wss://cdn.example.com/ws-imperva-test",
			RealIP:             serverAddr,
			HostHeader:         "cdn.example.com",
			SNI:                "safaricom.com",
			WSHeartbeat:        80 * time.Millisecond,
			Fingerprint:        transport.FingerprintChrome,
			PSK:                psk,
			InsecureSkipVerify: &insecureTrue,
		})
		if err != nil {
			t.Fatalf("NewClient: %v", err)
		}
		defer clt.Close()

		if err := clt.Connect(ctx); err != nil {
			t.Fatalf("client Connect over WSS uTLS: %v", err)
		}

		st, err := clt.OpenStream(ctx)
		if err != nil {
			t.Fatalf("OpenStream: %v", err)
		}
		defer st.Close()

		payload1 := []byte("FGXP_CDN_WS_PAYLOAD")
		if _, err := st.Write(payload1); err != nil {
			t.Fatalf("stream write 1: %v", err)
		}
		buf := make([]byte, 64)
		want1 := "ECHO:FGXP_CDN_WS_PAYLOAD"
		n, err := io.ReadFull(st, buf[:len(want1)])
		if err != nil {
			t.Fatalf("stream read 1: %v", err)
		}
		if string(buf[:n]) != want1 {
			t.Fatalf("got %q, want %q", buf[:n], want1)
		}

		// Allow periodic Ping keepalive goroutine to fire cleanly while writing/reading again
		time.Sleep(220 * time.Millisecond)

		payload2 := []byte("AFTER_PING")
		if _, err := st.Write(payload2); err != nil {
			t.Fatalf("stream write 2: %v", err)
		}
		want2 := "ECHO:AFTER_PING"
		n, err = io.ReadFull(st, buf[:len(want2)])
		if err != nil {
			t.Fatalf("stream read 2: %v", err)
		}
		if string(buf[:n]) != want2 {
			t.Fatalf("got %q, want %q", buf[:n], want2)
		}
	})

	t.Run("WS_NoTLS_Plaintext_Origin", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Server.Transport = "ws"
		cfg.Server.WSPath = "/ws-plain"
		cfg.Server.NoTLS = true
		cfg.Server.BehindCDN = true
		cfg.Stealth.Camouflage.Mode = "static"
		cfg.Stealth.Timing.Enabled = false
		cfg.Stealth.Padding.Enabled = false

		srv, err := server.NewServer(server.ServerOptions{
			ListenAddr:    "127.0.0.1:0",
			TransportType: transport.TCP,
			NoTLS:         true,
			PSK:           psk,
			Config:        cfg,
		})
		if err != nil {
			t.Fatalf("NewServer plaintext ws: %v", err)
		}
		defer srv.Close()

		srv.OnStream(func(st *stream.Stream) {
			defer st.Close()
			buf := make([]byte, 128)
			n, err := st.Read(buf)
			if err != nil && err != io.EOF {
				return
			}
			_, _ = st.Write(append([]byte("PLAIN:"), buf[:n]...))
		})

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() { _ = srv.ListenAndServe(ctx) }()
		serverAddr := waitServerAddr(t, srv)

		clt, err := client.NewClient(client.ClientOptions{
			WSURL:      "ws://" + serverAddr + "/ws-plain",
			HostHeader: "safaricom.com",
			PSK:        psk,
		})
		if err != nil {
			t.Fatalf("NewClient plaintext ws: %v", err)
		}
		defer clt.Close()

		if err := clt.Connect(ctx); err != nil {
			t.Fatalf("Connect plaintext ws: %v", err)
		}
		st, err := clt.OpenStream(ctx)
		if err != nil {
			t.Fatalf("OpenStream: %v", err)
		}
		defer st.Close()

		if _, err := st.Write([]byte("ORIGIN_OK")); err != nil {
			t.Fatalf("write: %v", err)
		}
		buf := make([]byte, 32)
		want := "PLAIN:ORIGIN_OK"
		n, err := io.ReadFull(st, buf[:len(want)])
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if !bytes.Equal(buf[:n], []byte(want)) {
			t.Fatalf("got %q, want %q", buf[:n], want)
		}
	})
}

func TestWebSocketProbeCamouflage(t *testing.T) {
	_, certPem, keyPem := generateSelfSignedCert(t)
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")
	decoyDir := filepath.Join(tmpDir, "www")
	if err := os.MkdirAll(decoyDir, 0755); err != nil {
		t.Fatalf("mkdir decoy: %v", err)
	}
	if err := os.WriteFile(filepath.Join(decoyDir, "index.html"), []byte("<html><body>DEC_OK_MARKER</body></html>"), 0644); err != nil {
		t.Fatalf("write decoy html: %v", err)
	}
	if err := os.WriteFile(certPath, certPem, 0600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPem, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Server.Transport = "ws"
	cfg.Server.WSPath = "/ws-secret-path"
	cfg.Server.BehindCDN = true
	cfg.Stealth.Camouflage.Mode = "static"
	cfg.Stealth.Camouflage.StaticDir = decoyDir

	srv, err := server.NewServer(server.ServerOptions{
		ListenAddr:    "127.0.0.1:0",
		TransportType: transport.TCP,
		TLSCertFile:   certPath,
		TLSKeyFile:    keyPath,
		PSK:           []byte("probe-camouflage-key-32-bytes!!!!"),
		Config:        cfg,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	serverAddr := waitServerAddr(t, srv)

	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	validKey := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef"))

	cases := []struct {
		name    string
		path    string
		headers map[string]string
	}{
		{
			name: "standard_browser_GET_root",
			path: "/",
		},
		{
			name: "ws_upgrade_wrong_path",
			path: "/",
			headers: map[string]string{
				"Upgrade":               "websocket",
				"Connection":            "Upgrade",
				"Sec-WebSocket-Version": "13",
				"Sec-WebSocket-Key":     validKey,
			},
		},
		{
			name: "ws_path_plain_GET",
			path: "/ws-secret-path",
		},
		{
			name: "ws_path_invalid_ws_key",
			path: "/ws-secret-path",
			headers: map[string]string{
				"Upgrade":               "websocket",
				"Connection":            "Upgrade",
				"Sec-WebSocket-Version": "13",
				"Sec-WebSocket-Key":     "bad-short-key",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "https://"+serverAddr+tc.path, nil)
			if err != nil {
				t.Fatalf("NewRequest: %v", err)
			}
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}
			resp, err := httpClient.Do(req)
			if err != nil {
				t.Fatalf("http Do: %v", err)
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != http.StatusOK {
				t.Fatalf("expected 200 OK decoy response, got %d (body=%q)", resp.StatusCode, string(body))
			}
			if !strings.Contains(string(body), "DEC_OK_MARKER") {
				t.Fatalf("expected decoy marker in body, got %q", string(body))
			}
			if resp.Header.Get("Server") == "" {
				t.Fatalf("expected Server header on decoy response")
			}
		})
	}
}

func TestHandshakeTimeoutZeroByteProbe(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.NoTLS = true
	cfg.Limits.HandshakeTimeout = 200 * time.Millisecond

	srv, err := server.NewServer(server.ServerOptions{
		ListenAddr:    "127.0.0.1:0",
		TransportType: transport.TCP,
		NoTLS:         true,
		PSK:           []byte("timeout-test-key-32-bytes-minimum"),
		Config:        cfg,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	serverAddr := waitServerAddr(t, srv)

	rawConn, err := net.Dial("tcp", serverAddr)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer rawConn.Close()

	// Send 0 bytes and wait for server HandshakeTimeout to terminate stalled connection
	_ = rawConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 8)
	start := time.Now()
	_, err = rawConn.Read(buf)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatalf("expected error/EOF on silent stalled probe, read succeeded")
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("expected handshake timeout within ~200ms (<1.5s), took %v", elapsed)
	}
}

func TestServerValidationErrors(t *testing.T) {
	baseOpts := func(cfg *config.ServerConfig) server.ServerOptions {
		return server.ServerOptions{
			ListenAddr:    "127.0.0.1:0",
			TransportType: transport.TCP,
			NoTLS:         true,
			PSK:           []byte("validation-test-key-32-bytes-min"),
			Config:        cfg,
		}
	}

	t.Run("unsupported_websocket_transport_name", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Server.Transport = "websocket"
		if _, err := server.NewServer(baseOpts(cfg)); err == nil {
			t.Fatalf("expected error for unsupported transport 'websocket'")
		}
	})

	t.Run("ws_path_cannot_be_root", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Server.Transport = "ws"
		cfg.Server.WSPath = "/"
		if _, err := server.NewServer(baseOpts(cfg)); err == nil {
			t.Fatalf("expected error for ws_path '/'")
		}
	})

	t.Run("ws_path_requires_leading_slash", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Server.Transport = "ws"
		cfg.Server.WSPath = "ws-no-slash"
		if _, err := server.NewServer(baseOpts(cfg)); err == nil {
			t.Fatalf("expected error for ws_path missing leading '/'")
		}
	})

	t.Run("ws_transport_requires_ws_path", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Server.Transport = "ws"
		cfg.Server.WSPath = ""
		if _, err := server.NewServer(baseOpts(cfg)); err == nil {
			t.Fatalf("expected error when transport is 'ws' without ws_path")
		}
	})

	t.Run("ws_path_conflicts_with_pluggable", func(t *testing.T) {
		cfg := config.DefaultConfig()
		cfg.Server.Transport = "ws"
		cfg.Server.WSPath = "/ws-conflict"
		cfg.Stealth.Pluggable.Enabled = true
		if _, err := server.NewServer(baseOpts(cfg)); err == nil {
			t.Fatalf("expected error when pluggable enabled alongside ws_path")
		}
	})
}

func TestClientInjectTLSWithKeepAliveRejected(t *testing.T) {
	clt, err := client.NewClient(client.ClientOptions{
		ServerAddr:   "127.0.0.1:80",
		InjectHost:   "safaricom.com",
		InjectMethod: "keepalive",
		InjectTLS:    true,
		PSK:          []byte("inject-keepalive-reject-32bytes"),
	})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	defer clt.Close()

	if err := clt.Connect(context.Background()); err == nil || !strings.Contains(err.Error(), "inject-tls") {
		t.Fatalf("expected inject-tls keepalive rejection error, got %v", err)
	}
}

func TestAuthDeadlineAndNonHTTPDropInWSMode(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Server.NoTLS = true
	cfg.Server.Transport = "ws"
	cfg.Server.WSPath = "/ws-drop"
	cfg.Limits.HandshakeTimeout = 200 * time.Millisecond

	srv, err := server.NewServer(server.ServerOptions{
		ListenAddr:    "127.0.0.1:0",
		TransportType: transport.TCP,
		NoTLS:         true,
		PSK:           []byte("ws-drop-auth-timeout-key-32bytes!"),
		Config:        cfg,
	})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.ListenAndServe(ctx) }()
	serverAddr := waitServerAddr(t, srv)

	t.Run("non_HTTP_probe_silently_dropped_in_ws_mode", func(t *testing.T) {
		c, err := net.Dial("tcp", serverAddr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer c.Close()

		// Non-HTTP, non-FGXP byte (e.g. SOCKS5 0x05)
		_, _ = c.Write([]byte{0x05, 0x01, 0x00})
		_ = c.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		buf := make([]byte, 64)
		n, err := c.Read(buf)
		if err == nil || n > 0 {
			t.Fatalf("expected silent drop (0 bytes + EOF/error), got n=%d (%q) err=%v", n, string(buf[:n]), err)
		}
	})

	t.Run("mid_auth_stall_enforces_HandshakeTimeout_after_0x19", func(t *testing.T) {
		c, err := net.Dial("tcp", serverAddr)
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}
		defer c.Close()

		// Send first byte of FrameAuth (0x19 = Version1<<4 | FrameAuth), then stall mid-auth
		firstByte := (byte(protocol.Version1) << 4) | byte(protocol.FrameAuth)
		if _, err := c.Write([]byte{firstByte}); err != nil {
			t.Fatalf("write 0x19: %v", err)
		}

		_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 16)
		start := time.Now()
		_, err = c.Read(buf)
		elapsed := time.Since(start)
		if err == nil {
			t.Fatalf("expected auth HandshakeTimeout close, read succeeded")
		}
		if elapsed > 1500*time.Millisecond {
			t.Fatalf("expected mid-auth deadline under 1.5s, took %v", elapsed)
		}
	})
}


