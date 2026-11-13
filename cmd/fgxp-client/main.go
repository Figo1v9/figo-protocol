// Command fgxp-client is the FGXP client binary / CLI tool.
//
// Usage:
//
//	fgxp-client --server example.com:443 --psk "secret" --sni "legitimate.com"
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"syscall"
	"crypto/tls"

	"github.com/figox/figox-protocol/pkg/client"
	"github.com/figox/figox-protocol/pkg/observability"
	"github.com/figox/figox-protocol/pkg/transport"
)

func main() {
	serverAddr := flag.String("server", "", "Server address (host:port; optional when --ws is specified)")
	psk := flag.String("psk", "", "Pre-shared key")
	sni := flag.String("sni", "", "SNI hostname for TLS handshake mimicry (e.g. safaricom.com)")
	hostHeader := flag.String("host", "", "Explicit HTTP Host header override (for CDN / WebSocket / HTTP framing)")
	realIP := flag.String("real-ip", "", "Target IP[:port] override (CDN edge IP / Domain Fronting)")
	injectHost := flag.String("inject", "", "Whitelisted host for HTTP Injection bypass (e.g. safaricom.com)")
	injectMethod := flag.String("inject-method", "connect", "Injection method: connect, front, keepalive")
	proxyAddr := flag.String("proxy", "", "Explicit HTTP proxy address (host:port) for --inject mode")
	injectTLS := flag.Bool("inject-tls", false, "Layer uTLS inside HTTP CONNECT / front injection tunnel")
	wsURL := flag.String("ws", "", "RFC 6455 WebSocket URL (e.g. wss://your-domain.com/ws-secret or wss://relay.workers.dev)")
	fingerprint := flag.String("fingerprint", transport.FingerprintChrome, "TLS fingerprint mimicry: chrome, firefox, edge, randomized, none")
	insecure := flag.Bool("insecure", true, "Skip TLS certificate verification (for self-signed certs / CDN fronting)")
	transportType := flag.String("transport", "tcp", "Transport: tcp or quic")
	socksListen := flag.String("socks-listen", "127.0.0.1:1080", "SOCKS5 proxy listen address (host:port)")
	logLevel := flag.String("log-level", "info", "Log level")
	flag.Parse()

	logger := observability.NewLogger(*logLevel, "json")

	if *serverAddr == "" && *wsURL == "" {
		logger.Error("--server or --ws is required")
		flag.Usage()
		os.Exit(1)
	}
	if *psk == "" {
		logger.Error("--psk is required")
		flag.Usage()
		os.Exit(1)
	}
	if *injectTLS && *injectMethod == "keepalive" {
		logger.Error("--inject-tls cannot be used with --inject-method keepalive")
		os.Exit(1)
	}

	logger.Info("FGXP client starting",
		"server", *serverAddr,
		"ws", *wsURL,
		"transport", *transportType,
		"fingerprint", *fingerprint,
		"sni", *sni,
		"host", *hostHeader,
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received signal, disconnecting", "signal", sig)
		cancel()
	}()

	// Map transport type string to transport.Type
	var transType transport.Type
	if *transportType == "quic" {
		transType = transport.QUIC
	} else {
		transType = transport.TCP
	}

	insecureSkipVerify := *insecure
	clt, err := client.NewClient(client.ClientOptions{
		ServerAddr:         *serverAddr,
		RealIP:             *realIP,
		HostHeader:         *hostHeader,
		InjectHost:         *injectHost,
		InjectMethod:       *injectMethod,
		ProxyAddr:          *proxyAddr,
		InjectTLS:          *injectTLS,
		WSURL:              *wsURL,
		Fingerprint:        *fingerprint,
		TransportType:      transType,
		PSK:                []byte(*psk),
		SNI:                *sni,
		InsecureSkipVerify: &insecureSkipVerify,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: insecureSkipVerify,
		},
	})
	if err != nil {
		logger.Error("failed to create client", "error", err)
		os.Exit(1)
	}
	defer clt.Close()

	if err := clt.Connect(ctx); err != nil {
		logger.Error("failed to connect", "error", err)
		os.Exit(1)
	}

	// Start local SOCKS5 listener
	socksLn, err := net.Listen("tcp", *socksListen)
	if err != nil {
		logger.Error("failed to start SOCKS5 listener", "error", err)
		os.Exit(1)
	}
	defer socksLn.Close()
	logger.Info("SOCKS5 Proxy listener started", "addr", *socksListen)

	go func() {
		for {
			conn, err := socksLn.Accept()
			if err != nil {
				return
			}
			go handleSOCKS5(conn, clt, logger, ctx)
		}
	}()

	<-ctx.Done()
	logger.Info("FGXP client stopped")
}

func handleSOCKS5(conn net.Conn, clt *client.Client, logger *observability.Logger, ctx context.Context) {
	defer conn.Close()

	// 1. Read greeting
	var buf [262]byte
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return
	}
	if buf[0] != 5 {
		return // SOCKS5 only
	}
	nmethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nmethods]); err != nil {
		return
	}

	// Respond with no auth
	if _, err := conn.Write([]byte{5, 0}); err != nil {
		return
	}

	// 2. Read request
	if _, err := io.ReadFull(conn, buf[:4]); err != nil {
		return
	}
	if buf[1] != 1 {
		return // CONNECT command only
	}

	var host string
	switch buf[3] {
	case 1: // IPv4
		var ip [4]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	case 3: // Domain name
		var domainLenBuf [1]byte
		if _, err := io.ReadFull(conn, domainLenBuf[:]); err != nil {
			return
		}
		domainLen := int(domainLenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return
		}
		host = string(domainBuf)
	case 4: // IPv6
		var ip [16]byte
		if _, err := io.ReadFull(conn, ip[:]); err != nil {
			return
		}
		host = net.IP(ip[:]).String()
	default:
		return
	}

	var portBuf [2]byte
	if _, err := io.ReadFull(conn, portBuf[:]); err != nil {
		return
	}
	port := (int(portBuf[0]) << 8) | int(portBuf[1])
	targetAddr := fmt.Sprintf("%s:%d", host, port)

	// Connect/open stream
	st, err := clt.OpenStream(ctx)
	if err != nil {
		_, _ = conn.Write([]byte{5, 1, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer st.Close()

	// Write target address as the first line of the stream
	_, err = st.Write([]byte(targetAddr + "\n"))
	if err != nil {
		return
	}

	// Respond with success
	if _, err := conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
		return
	}

	// Pipe bidirectional stream with 32KB buffers (stays safely under 64KB MaxPayloadLength after padding)
	errCh := make(chan error, 2)
	go func() {
		buf := make([]byte, 32*1024)
		_, err := io.CopyBuffer(st, conn, buf)
		errCh <- err
	}()
	go func() {
		buf := make([]byte, 32*1024)
		_, err := io.CopyBuffer(conn, st, buf)
		errCh <- err
	}()

	<-errCh
}
