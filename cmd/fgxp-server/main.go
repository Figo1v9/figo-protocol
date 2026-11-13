// Command fgxp-server is the FGXP server binary.
//
// Usage:
//
//	fgxp-server --config /path/to/server.yaml
//	fgxp-server --listen :443 --cert cert.pem --key key.pem --psk "secret"
package main

import (
	"bufio"
	"bytes"
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/figox/figox-protocol/pkg/config"
	"github.com/figox/figox-protocol/pkg/observability"
	"github.com/figox/figox-protocol/pkg/server"
	"github.com/figox/figox-protocol/pkg/stream"
	"github.com/figox/figox-protocol/pkg/transport"
)

func main() {
	configPath := flag.String("config", "", "Path to server configuration file (YAML)")
	listenAddr := flag.String("listen", ":443", "Listen address")
	certPath := flag.String("cert", "", "TLS certificate file")
	keyPath := flag.String("key", "", "TLS private key file")
	noTLS := flag.Bool("no-tls", false, "Disable TLS for plaintext HTTP framing (port 80)")
	psk := flag.String("psk", "", "Pre-shared key for authentication")
	logLevel := flag.String("log-level", "info", "Log level (debug, info, warn, error)")
	flag.Parse()

	logger := observability.NewLogger(*logLevel, "json")
	metrics := observability.NewMetrics()
	health := observability.NewHealthChecker(metrics)

	var cfg *config.ServerConfig
	var err error

	if *configPath != "" {
		cfg, err = config.LoadServerConfig(*configPath)
		if err != nil {
			logger.Error("failed to load config", "path", *configPath, "error", err)
			os.Exit(1)
		}
	} else {
		cfg = config.DefaultConfig()
		cfg.Server.Listen = *listenAddr
		cfg.Server.Transport = "tcp"
		cfg.TLS.Cert = *certPath
		cfg.TLS.Key = *keyPath
		cfg.Auth.Method = "psk"
		cfg.Auth.Keys = []config.KeyConfig{
			{ID: "default", Secret: *psk},
		}
	}

	logger.Info("FGXP server starting",
		"listen", cfg.Server.Listen,
		"transport", cfg.Server.Transport,
	)

	// Setup graceful shutdown.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, shutting down", "signal", sig)
		cancel()
	}()

	health.SetReady(true)

	// Map transport type string to transport.Type
	var transType transport.Type
	switch cfg.Server.Transport {
	case "quic":
		transType = transport.QUIC
	case "both":
		transType = transport.Both
	default:
		transType = transport.TCP
	}

	var keyBytes []byte
	if len(cfg.Auth.Keys) > 0 {
		keyBytes = []byte(cfg.Auth.Keys[0].Secret)
	}

	srv, err := server.NewServer(server.ServerOptions{
		ListenAddr:    cfg.Server.Listen,
		TransportType: transType,
		TLSCertFile:   cfg.TLS.Cert,
		TLSKeyFile:    cfg.TLS.Key,
		NoTLS:         *noTLS,
		PSK:           keyBytes,
		Config:        cfg,
	})
	if err != nil {
		logger.Error("failed to create server", "error", err)
		os.Exit(1)
	}
	srv.OnStream(func(st *stream.Stream) {
		defer st.Close()

		// Read target address (first line, up to '\n')
		reader := bufio.NewReader(st)
		targetAddrBytes, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		targetAddr := string(bytes.TrimSpace(targetAddrBytes))

		// Dial target host over IPv4
		targetConn, err := net.DialTimeout("tcp4", targetAddr, 10*time.Second)
		if err != nil {
			logger.Error("failed to dial target host", "host", targetAddr, "error", err)
			return
		}
		defer targetConn.Close()

		// Pipe bidirectional stream with 32KB buffers (stays safely under 64KB MaxPayloadLength after padding)
		errCh := make(chan error, 2)
		go func() {
			buf := make([]byte, 32*1024)
			_, err := io.CopyBuffer(targetConn, reader, buf) // copy remaining bytes from bufio reader first
			errCh <- err
		}()
		go func() {
			buf := make([]byte, 32*1024)
			_, err := io.CopyBuffer(st, targetConn, buf)
			errCh <- err
		}()

		<-errCh
	})

	defer srv.Close()

	logger.Info("FGXP server ready",
		"listen", cfg.Server.Listen,
		"metrics", fmt.Sprintf("active_connections=%d", metrics.ActiveConnections.Load()),
	)

	// Run server in a goroutine
	srvErrCh := make(chan error, 1)
	go func() {
		srvErrCh <- srv.ListenAndServe(ctx)
	}()

	select {
	case err := <-srvErrCh:
		if err != nil {
			logger.Error("server listener error", "error", err)
		}
	case <-ctx.Done():
		logger.Info("shutting down server")
	}

	health.SetReady(false)
	logger.Info("FGXP server stopped", "uptime", metrics.Uptime())
}
