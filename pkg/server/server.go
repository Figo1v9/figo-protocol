// Package server implements the FGXP server which accepts transport connections,
// handles active prober camouflage fallback, authenticates clients, and manages
// multiplexed sessions and streams.
package server

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/figox/figox-protocol/internal/buffer"
	"github.com/figox/figox-protocol/pkg/auth"
	"github.com/figox/figox-protocol/pkg/compress"
	"github.com/figox/figox-protocol/pkg/config"
	"github.com/figox/figox-protocol/pkg/observability"
	"github.com/figox/figox-protocol/pkg/plugin"
	"github.com/figox/figox-protocol/pkg/protocol"
	"github.com/figox/figox-protocol/pkg/session"
	"github.com/figox/figox-protocol/pkg/stealth"
	"github.com/figox/figox-protocol/pkg/stream"
	"github.com/figox/figox-protocol/pkg/transport"
	"github.com/gorilla/websocket"
)

// ServerOptions configures the FGXP server.
type ServerOptions struct {
	ListenAddr    string
	TransportType transport.Type
	TLSCertFile   string
	TLSKeyFile    string
	NoTLS         bool
	PSK           []byte
	Config        *config.ServerConfig
}

// Server represents an FGXP server.
type Server struct {
	opts          ServerOptions
	logger        *observability.Logger
	metrics       *observability.Metrics
	plugins       *plugin.Registry
	pskStore      *auth.MemoryPSKStore
	authenticator *auth.PSKAuthenticator
	stealthEngine *stealth.Engine
	reverseProxy  *httputil.ReverseProxy
	httpListener  *chanListener
	httpServer    *http.Server
	wsUpgrader    websocket.Upgrader
	wsPath        string
	serverHeader  string

	mu         sync.Mutex
	listeners  []transport.Listener
	sessions   map[string]*SessionContext
	streamFunc func(*stream.Stream)
	ctx        context.Context
	cancel     context.CancelFunc
}

// SessionContext wraps a session, its transport, multiplexer, and write queue.
type SessionContext struct {
	Session *session.Session
	Conn    transport.Conn
	Mux     *stream.Mux
	Writer  *SessionWriter
}

// SessionWriter coordinates thread-safe and stealthy writing to the transport connection.
type SessionWriter struct {
	conn       transport.Conn
	engine     *stealth.Engine
	writeQueue chan *protocol.Frame
	ctx        context.Context
	cancel     context.CancelFunc
	metrics    *observability.Metrics
}

// NewServer creates a new FGXP server.
func NewServer(opts ServerOptions) (*Server, error) {
	if opts.Config == nil {
		opts.Config = config.DefaultConfig()
	}

	switch opts.Config.Server.Transport {
	case "", "tcp", "quic", "both", "ws":
	default:
		return nil, fmt.Errorf("fgxp/server: unsupported transport %q", opts.Config.Server.Transport)
	}

	wsPath := strings.TrimSpace(opts.Config.Server.WSPath)
	if wsPath != "" {
		if !strings.HasPrefix(wsPath, "/") {
			return nil, fmt.Errorf("fgxp/server: server.ws_path must start with '/' (got %q)", wsPath)
		}
		if wsPath == "/" {
			return nil, fmt.Errorf("fgxp/server: server.ws_path cannot be '/' (must be a secret path)")
		}
		if opts.Config.Stealth.Pluggable.Enabled {
			return nil, fmt.Errorf("fgxp/server: stealth.pluggable cannot be enabled alongside HTTP/WS server mode (ws_path)")
		}
	}
	if opts.Config.Server.Transport == "ws" && wsPath == "" {
		return nil, fmt.Errorf("fgxp/server: server.ws_path is required when server.transport is 'ws'")
	}

	logger := observability.NewLogger(opts.Config.Observability.Logging.Level, opts.Config.Observability.Logging.Format)
	metrics := observability.NewMetrics()
	plugins := plugin.NewRegistry()

	pskStore := auth.NewMemoryPSKStore()
	if len(opts.PSK) > 0 {
		pskStore.AddKey(opts.PSK)
	}
	for _, keyCfg := range opts.Config.Auth.Keys {
		pskStore.AddKey([]byte(keyCfg.Secret))
	}

	authenticator := auth.NewPSKAuthenticator(pskStore)
	stealthEngine := stealth.NewEngine(config.ToStealthConfig(&opts.Config.Stealth))

	serverHeader := opts.Config.Stealth.Camouflage.ServerHeader
	if serverHeader == "" {
		serverHeader = stealth.DefaultServerHeader
	}

	ctx, cancel := context.WithCancel(context.Background())

	srv := &Server{
		opts:          opts,
		logger:        logger,
		metrics:       metrics,
		plugins:       plugins,
		pskStore:      pskStore,
		authenticator: authenticator,
		stealthEngine: stealthEngine,
		wsPath:        wsPath,
		serverHeader:  serverHeader,
		sessions:      make(map[string]*SessionContext),
		ctx:           ctx,
		cancel:        cancel,
	}

	srv.initCamouflageAndWS()
	return srv, nil
}

func (s *Server) handshakeTimeout() time.Duration {
	if s.opts.Config != nil && s.opts.Config.Limits.HandshakeTimeout > 0 {
		return s.opts.Config.Limits.HandshakeTimeout
	}
	return protocol.DefaultHandshakeTimeout
}

func (s *Server) idleTimeout() time.Duration {
	if s.opts.Config != nil && s.opts.Config.Limits.IdleTimeout > 0 {
		return s.opts.Config.Limits.IdleTimeout
	}
	return 5 * time.Minute
}

func (s *Server) initCamouflageAndWS() {
	cfg := &s.opts.Config.Stealth.Camouflage
	if cfg.Mode == "reverse_proxy" && cfg.ProxyTarget != "" {
		targetURL, err := url.Parse(cfg.ProxyTarget)
		if err != nil || targetURL.Host == "" {
			s.logger.Error("invalid camouflage proxy target, falling back to static", "url", cfg.ProxyTarget, "error", err)
		} else {
			if targetURL.Scheme == "" {
				targetURL.Scheme = "https"
			}
			rp := &httputil.ReverseProxy{
				Rewrite: func(pr *httputil.ProxyRequest) {
					pr.SetURL(targetURL)
					pr.Out.Host = targetURL.Host
					if pr.Out.Header.Get("User-Agent") == "" {
						pr.Out.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36")
					}
					pr.Out.Header.Del("Incap-Client-IP")
					pr.Out.Header.Del("CF-Connecting-IP")
					pr.Out.Header.Del("CF-IPCountry")
				},
				Transport: &http.Transport{
					TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
					MaxIdleConnsPerHost:   32,
					IdleConnTimeout:       60 * time.Second,
					ResponseHeaderTimeout: 10 * time.Second,
				},
				ModifyResponse: func(resp *http.Response) error {
					resp.Header.Set("Server", s.serverHeader)
					return nil
				},
				ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
					s.logger.Warn("camouflage proxy request failed, serving static decoy", "error", err)
					s.serveStaticDecoyHTTP(w, r)
				},
			}
			s.reverseProxy = rp
		}
	}

	s.wsUpgrader = websocket.Upgrader{
		EnableCompression: false,
		CheckOrigin:       func(*http.Request) bool { return true },
		Error: func(w http.ResponseWriter, r *http.Request, _ int, _ error) {
			s.serveHTTPDecoy(w, r)
		},
	}

	if s.wsPath != "" {
		s.httpListener = newChanListener()
		s.httpServer = &http.Server{
			Handler:           http.HandlerFunc(s.serveWSOrDecoyHTTP),
			ReadHeaderTimeout: s.handshakeTimeout(),
			IdleTimeout:       s.idleTimeout(),
			ErrorLog:          log.New(io.Discard, "", 0),
			ConnContext: func(ctx context.Context, c net.Conn) context.Context {
				if hc, ok := c.(*httpCandidateConn); ok {
					return context.WithValue(ctx, httpCandidateCtxKey{}, hc)
				}
				return ctx
			},
			ConnState: func(c net.Conn, state http.ConnState) {
				if state == http.StateClosed || state == http.StateHijacked {
					if hc, ok := c.(*httpCandidateConn); ok {
						hc.notifyState(state)
					}
				}
			},
		}
	}
}

// OnStream sets the callback function to invoke when a new stream is opened.
func (s *Server) OnStream(fn func(*stream.Stream)) {
	s.mu.Lock()
	s.streamFunc = fn
	s.mu.Unlock()
}

// ListenAndServe starts the server listeners and accepts connections.
// It blocks until the context is cancelled or the server is closed.
func (s *Server) ListenAndServe(ctx context.Context) error {
	tlsCfg, err := s.loadTLSConfig()
	if err != nil {
		return err
	}

	var listeners []transport.Listener

	// Listen on TCP (includes "ws" WebSocket-over-HTTP/HTTPS mode)
	if s.opts.TransportType == transport.TCP || s.opts.TransportType == transport.Both {
		var l transport.Listener
		var err error
		if tlsCfg != nil {
			l, err = transport.ListenTCP(s.opts.ListenAddr, tlsCfg)
		} else {
			l, err = transport.ListenRawTCP(s.opts.ListenAddr)
		}
		if err != nil {
			return err
		}
		listeners = append(listeners, l)
		if tlsCfg != nil {
			s.logger.Info("Listening on TCP+TLS", "addr", s.opts.ListenAddr, "ws_path", s.wsPath)
		} else {
			s.logger.Info("Listening on Raw TCP (HTTP / WS)", "addr", s.opts.ListenAddr, "ws_path", s.wsPath)
		}
	}

	// Listen on QUIC
	if s.opts.TransportType == transport.QUIC || s.opts.TransportType == transport.Both {
		l, err := transport.ListenQUIC(s.opts.ListenAddr, tlsCfg)
		if err != nil {
			// Clean up TCP listeners if QUIC fails
			for _, ln := range listeners {
				ln.Close()
			}
			return err
		}
		listeners = append(listeners, l)
		s.logger.Info("Listening on QUIC (HTTP/3 Mimicry)", "addr", s.opts.ListenAddr)
	}

	if s.httpServer != nil && s.httpListener != nil {
		go func() {
			_ = s.httpServer.Serve(s.httpListener)
		}()
	}

	s.mu.Lock()
	s.listeners = listeners
	s.mu.Unlock()

	var wg sync.WaitGroup
	for _, l := range listeners {
		wg.Add(1)
		go func(ln transport.Listener) {
			defer wg.Done()
			s.acceptLoop(ctx, ln)
		}(l)
	}

	wg.Wait()
	return nil
}

// Close stops the server and closes all listeners, HTTP keep-alive servers, and active sessions.
func (s *Server) Close() error {
	s.cancel()

	if s.httpServer != nil {
		_ = s.httpServer.Close()
	}
	if s.httpListener != nil {
		_ = s.httpListener.Close()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, l := range s.listeners {
		l.Close()
	}

	for _, sc := range s.sessions {
		sc.Conn.Close()
		sc.Mux.Close()
		sc.Writer.Close()
	}

	return nil
}

// Addr returns the address of the first listener (TCP or QUIC).
// Returns nil if the server is not listening yet.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.listeners) > 0 {
		return s.listeners[0].Addr()
	}
	return nil
}

func generateEphemeralCert() (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"FGXP Camouflage Node"},
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{
		Certificate: [][]byte{derBytes},
		PrivateKey:  priv,
	}, nil
}

func (s *Server) loadTLSConfig() (*tls.Config, error) {
	if s.opts.NoTLS || (s.opts.Config != nil && s.opts.Config.Server.NoTLS) {
		return nil, nil
	}
	var cert tls.Certificate
	var err error

	if s.opts.TLSCertFile != "" && s.opts.TLSKeyFile != "" {
		cert, err = tls.LoadX509KeyPair(s.opts.TLSCertFile, s.opts.TLSKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load x509 key pair: %w", err)
		}
	} else {
		// Auto-generate ephemeral ECDSA TLS cert for zero-config startup
		cert, err = generateEphemeralCert()
		if err != nil {
			return nil, fmt.Errorf("failed to generate ephemeral tls cert: %w", err)
		}
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{"http/1.1"},
	}, nil
}

func (s *Server) acceptLoop(ctx context.Context, ln transport.Listener) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.ctx.Done():
			return
		default:
			conn, err := ln.Accept(ctx)
			if err != nil {
				s.logger.Debug("accept connection error", "error", err)
				continue
			}

			go s.handleConnection(conn)
		}
	}
}

// connReadWriter wraps transport.Conn to support frame-level reads/writes for auth.
type connReadWriter struct {
	conn transport.Conn
}

func (crw *connReadWriter) SetDeadline(t time.Time) error {
	return crw.conn.SetDeadline(t)
}

func (crw *connReadWriter) ReadFrame() (*protocol.Frame, error) {
	return protocol.DecodeFrame(crw.conn)
}

func (crw *connReadWriter) WriteFrame(f *protocol.Frame) error {
	// Apply stealth padding to AUTH handshake frames so their on-wire size
	// varies and is not trivially fingerprintable. Lossless: DecodeFrame
	// strips padding before reconstruction; the HMAC is computed over the
	// logical payload. Fail-soft because dropping AUTH would deadlock.
	if err := stealth.ApplyPadding(f, stealth.NewEngine(nil)); err != nil {
		_ = err // non-fatal
	}
	_, err := f.EncodeTo(crw.conn)
	return err
}

func (s *Server) handleConnection(conn transport.Conn) {
	s.metrics.TotalConnections.Add(1)
	s.metrics.ActiveConnections.Add(1)
	defer s.metrics.ActiveConnections.Add(-1)

	// Legacy direct-TCP pluggable transport scrambling (forbidden alongside ws_path in NewServer).
	if s.wsPath == "" && s.opts.Config != nil && s.opts.Config.Stealth.Pluggable.Enabled {
		ptName := s.opts.Config.Stealth.Pluggable.Name
		if ptName == "" {
			ptName = "scramble"
		}
		if ptName == "scramble" {
			st := &transport.ScrambleTransport{Key: []byte(s.opts.Config.Stealth.Pluggable.Secret), IsServer: true}
			wrapped, err := st.WrapConn(conn)
			if err != nil {
				conn.Close()
				return
			}
			conn = wrapped
		}
	}

	if conn.TransportType() == transport.QUIC {
		s.authenticateAndServe(conn)
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(s.handshakeTimeout()))
	peekable := newPeekConn(conn)
	firstByte, err := peekable.PeekFirstByte()
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		s.logger.Debug("no recognizable first byte; closing as probe", "error", err)
		conn.Close()
		return
	}

	if auth.IsFirstByteFGXP(firstByte) {
		s.authenticateAndServe(peekable)
		return
	}

	// Modern CDN / RFC 6455 WebSocket + keep-alive decoy mode.
	if s.wsPath != "" {
		if !stealth.IsHTTPMethodByte(firstByte) {
			s.logger.Debug("non-HTTP garbage byte dropped silently", "remote", conn.RemoteAddr().String())
			conn.Close()
			return
		}

		hc := newHTTPCandidateConn(peekable, conn.ConnectionState())
		if !s.httpListener.Enqueue(s.ctx, hc) {
			_ = peekable.Close()
			return
		}

		var finalState http.ConnState
		select {
		case finalState = <-hc.stateCh:
		case <-s.ctx.Done():
			_ = peekable.Close()
			return
		}

		if finalState != http.StateHijacked {
			return // net/http.Server owns closing non-hijacked HTTP connections.
		}

		select {
		case ws := <-hc.wsCh:
			if ws == nil {
				return
			}
			wsConn := transport.WrapWebSocketConn(ws, hc.RemoteAddr(), hc.tlsState)
			s.authenticateAndServe(wsConn)
		case <-s.ctx.Done():
			return
		}
		return
	}

	// Legacy direct mode (no ws_path configured): allow optional L7 HTTP Upgrade
	// framing and route regular HTTP probes to camouflage.
	_ = peekable.SetReadDeadline(time.Now().Add(s.handshakeTimeout()))
	framedConn, upgraded, err := transport.HandleHTTPFramingServer(peekable)
	_ = peekable.SetReadDeadline(time.Time{})
	if err != nil {
		s.logger.Debug("invalid legacy http framing probe; closing", "error", err)
		conn.Close()
		return
	}
	if upgraded {
		s.authenticateAndServe(framedConn)
		return
	}

	s.logger.Info("non-FGXP traffic detected, routing to camouflage server", "remote", conn.RemoteAddr().String())
	s.handleCamouflage(newPeekConn(framedConn))
}

func (s *Server) authenticateAndServe(conn transport.Conn) {
	// Step 1: Authenticate the connection under HandshakeTimeout. Any auth error
	// closes silently without emitting FGXP-specific hints.
	crw := &connReadWriter{conn: conn}
	authCtx, authCancel := context.WithTimeout(s.ctx, s.handshakeTimeout())
	authRes, err := s.authenticator.Authenticate(authCtx, crw)
	authCancel()
	if err != nil || !authRes.Success {
		s.metrics.AuthFailures.Add(1)
		s.logger.Warn("authentication failed", "error", err, "reason", authRes.ErrorMessage)
		conn.Close()
		return
	}

	s.metrics.AuthSuccesses.Add(1)
	s.logger.Info("client authenticated successfully", "session", fmt.Sprintf("%x", authRes.SessionID))

	// Step 2: Establish session contexts
	sess := session.NewSession(s.ctx)
	sess.SetAuth(authRes.SessionID, authRes.ResumptionToken, authRes.TokenExpiry)
	_ = sess.Transition(session.StateConnecting)
	_ = sess.Transition(session.StateAuthenticating)
	_ = sess.Transition(session.StateActive)

	mux := stream.NewMux(s.ctx)
	writerCtx, writerCancel := context.WithCancel(s.ctx)
	writer := &SessionWriter{
		conn:       conn,
		engine:     s.stealthEngine,
		writeQueue: make(chan *protocol.Frame, 4096),
		ctx:        writerCtx,
		cancel:     writerCancel,
		metrics:    s.metrics,
	}

	sc := &SessionContext{
		Session: sess,
		Conn:    conn,
		Mux:     mux,
		Writer:  writer,
	}

	s.mu.Lock()
	s.sessions[sess.ID()] = sc
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.sessions, sess.ID())
		s.mu.Unlock()

		conn.Close()
		mux.Close()
		writer.Close()
		sess.Transition(session.StateClosed)
	}()

	// Start connection write loop
	go writer.Start()

	// Start connection read loop
	s.runReadLoop(sc)
}

func (s *Server) runReadLoop(sc *SessionContext) {
	for {
		f, err := protocol.DecodeFrame(sc.Conn)
		if err != nil {
			if err != io.EOF {
				s.logger.Error("decode frame error", "session", sc.Session.ID(), "error", err)
			}
			return
		}

		s.metrics.FramesReceived.Add(1)
		s.metrics.BytesReceived.Add(int64(f.TotalSize()))

		if err := f.Validate(); err != nil {
			s.logger.Warn("invalid frame received", "session", sc.Session.ID(), "error", err)
			sc.Writer.QueueFrame(&protocol.Frame{
				Version:  protocol.CurrentVersion,
				Type:     protocol.FrameGoAway,
				StreamID: protocol.ControlStreamID,
				Payload:  []byte{0, 0, 0, byte(protocol.ErrProtocol)},
			})
			return
		}

		s.handleFrame(sc, f)
	}
}

func (s *Server) handleFrame(sc *SessionContext, f *protocol.Frame) {
	if f.IsControl() || f.Type == protocol.FrameStreamOpen {
		s.handleControlFrame(sc, f)
		return
	}

	st, exists := sc.Mux.GetStream(f.StreamID)
	if !exists {
		// If data frame for unknown non-existent stream, ignore or reset.
		if f.Type == protocol.FrameData {
			sc.Writer.QueueFrame(&protocol.Frame{
				Version:  protocol.CurrentVersion,
				Type:     protocol.FrameStreamReset,
				StreamID: f.StreamID,
				Payload:  []byte{0, 0, 0, byte(protocol.ErrInvalidStreamID)},
			})
		}
		return
	}

	if f.Type == protocol.FrameData {
		// Support decompressive reads if compression flag is present.
		data := f.Payload
		if f.Flags.Has(protocol.FlagCompressed) {
			alg := s.opts.Config.Compression.Algorithm
			var comp compress.Compressor
			var err error
			switch alg {
			case "lz4":
				comp, err = compress.New(protocol.CompressionLZ4)
			case "zstd":
				comp, err = compress.New(protocol.CompressionZstd)
			default:
				comp, err = compress.New(protocol.CompressionNone)
			}

			if err == nil {
				decomp, err := comp.Decompress(f.Payload)
				if err == nil {
					data = decomp
				}
			}
		}

		st.DeliverData(data)
	} else if f.Type == protocol.FrameStreamClose {
		st.Close()
	} else if f.Type == protocol.FrameStreamReset {
		st.Close()
	} else if f.Type == protocol.FrameWindowUpdate {
		// Window size update
		if len(f.Payload) >= 8 {
			var delta int64 // big-endian uint64 or int64
			// Read 8 bytes
			for i := 0; i < 8; i++ {
				delta = (delta << 8) | int64(f.Payload[i])
			}
			st.UpdateSendWindow(delta)
		}
	}
}

func (s *Server) handleControlFrame(sc *SessionContext, f *protocol.Frame) {
	switch f.Type {
	case protocol.FrameStreamOpen:
		if len(f.Payload) < 2 {
			return
		}
		streamType := protocol.StreamType(f.Payload[0])
		priority := f.Payload[1]
		// Create and notify callback
		st := stream.NewStream(
			sc.Session.Context(),
			f.StreamID,
			streamType,
			priority,
			int64(s.opts.Config.Streams.InitialWindow),
			sc.Conn.LocalAddr(),
			sc.Conn.RemoteAddr(),
		)

		if err := sc.Mux.OpenStream(st); err != nil {
			return
		}

		s.metrics.TotalStreams.Add(1)
		s.metrics.ActiveStreams.Add(1)

		s.mu.Lock()
		callback := s.streamFunc
		s.mu.Unlock()

		if callback != nil {
			go func() {
				defer s.metrics.ActiveStreams.Add(-1)
				callback(st)
			}()
		}

		// Set up stream write handler
		go s.handleStreamWrites(sc, st)

	case protocol.FramePing:
		sc.Writer.QueueFrame(&protocol.Frame{
			Version:  protocol.CurrentVersion,
			Type:     protocol.FramePong,
			StreamID: protocol.ControlStreamID,
			Payload:  f.Payload,
		})

	case protocol.FrameGoAway:
		sc.Session.Transition(session.StateDraining)
		sc.Writer.Close()
	}
}

func (s *Server) handleStreamWrites(sc *SessionContext, st *stream.Stream) {
	defer sc.Mux.CloseStream(st.ID())

	for {
		select {
		case <-sc.Session.Context().Done():
			return
		case req, ok := <-st.DrainWrites():
			if !ok {
				return
			}

			// Apply flow control window checks.
			for {
				if st.SendWindow() >= int64(len(req.Data)) {
					break
				}
				// Wait for window update
				time.Sleep(10 * time.Millisecond)
			}

			// Optional compression
			var payload []byte = req.Data
			var flags protocol.Flags = 0
			alg := s.opts.Config.Compression.Algorithm
			if alg != "" && alg != "none" {
				var comp compress.Compressor
				var err error
				if alg == "lz4" {
					comp, err = compress.New(protocol.CompressionLZ4)
				} else if alg == "zstd" {
					comp, err = compress.New(protocol.CompressionZstd)
				}
				if err == nil {
					if dst, ok := comp.Compress(req.Data); ok {
						payload = dst
						flags = flags.Set(protocol.FlagCompressed)
					}
				}
			}

			frame := &protocol.Frame{
				Version:  protocol.CurrentVersion,
				Type:     protocol.FrameData,
				StreamID: st.ID(),
				Sequence: st.NextSendSequence(),
				Flags:    flags,
				Payload:  payload,
			}

			sc.Writer.QueueFrame(frame)
			req.Result <- stream.WriteResult{N: len(req.Data), Err: nil}
		}
	}
}

type writeResult struct {
	n   int
	err error
}

func (s *Server) extractClientIP(r *http.Request, fallback net.Addr) string {
	if s.opts.Config != nil && s.opts.Config.Server.BehindCDN {
		if ip := strings.TrimSpace(r.Header.Get("Incap-Client-IP")); ip != "" {
			return ip
		}
		if ip := strings.TrimSpace(r.Header.Get("CF-Connecting-IP")); ip != "" {
			return ip
		}
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if ip := strings.TrimSpace(first); ip != "" {
				return ip
			}
		}
	}
	if fallback != nil {
		return fallback.String()
	}
	return ""
}

func (s *Server) serveWSOrDecoyHTTP(w http.ResponseWriter, r *http.Request) {
	hc, _ := r.Context().Value(httpCandidateCtxKey{}).(*httpCandidateConn)
	if hc == nil || s.wsPath == "" || r.URL.Path != s.wsPath || !transport.IsWebSocketUpgradeRequest(r) {
		s.serveHTTPDecoy(w, r)
		return
	}

	clientIP := s.extractClientIP(r, hc.RemoteAddr())
	s.logger.Debug("upgrading incoming websocket session", "client_ip", clientIP, "path", r.URL.Path)

	respHdr := make(http.Header)
	respHdr.Set("Server", s.serverHeader)

	ws, err := s.wsUpgrader.Upgrade(w, r, respHdr)
	if err != nil {
		select {
		case hc.wsCh <- nil:
		default:
		}
		return
	}
	hc.wsCh <- ws
}

func (s *Server) serveHTTPDecoy(w http.ResponseWriter, r *http.Request) {
	if s.opts.Config != nil && s.opts.Config.Stealth.Camouflage.Mode == "none" {
		if hijacker, ok := w.(http.Hijacker); ok {
			if raw, _, err := hijacker.Hijack(); err == nil {
				_ = raw.Close()
				return
			}
		}
		w.Header().Set("Server", s.serverHeader)
		w.WriteHeader(http.StatusNotFound)
		return
	}

	if s.reverseProxy != nil {
		s.reverseProxy.ServeHTTP(w, r)
		return
	}
	s.serveStaticDecoyHTTP(w, r)
}

func (s *Server) serveStaticDecoyHTTP(w http.ResponseWriter, r *http.Request) {
	var body []byte
	if s.opts.Config != nil && s.opts.Config.Stealth.Camouflage.StaticDir != "" {
		cleanPath := filepath.Clean("/" + r.URL.Path)
		if cleanPath == "/" {
			cleanPath = "/index.html"
		}
		candidate := filepath.Join(s.opts.Config.Stealth.Camouflage.StaticDir, cleanPath)
		if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
			if data, readErr := os.ReadFile(candidate); readErr == nil {
				body = data
			}
		} else if fallbackData, readErr := os.ReadFile(filepath.Join(s.opts.Config.Stealth.Camouflage.StaticDir, "index.html")); readErr == nil {
			body = fallbackData
		}
	}

	if len(body) == 0 {
		body = []byte(`<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>
<style>
html { color-scheme: light dark; }
body { width: 35em; margin: 0 auto; font-family: Tahoma, Verdana, Arial, sans-serif; }
</style>
</head>
<body>
<h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed and working.</p>
</body>
</html>`)
	}

	w.Header().Set("Server", s.serverHeader)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (s *Server) handleCamouflage(conn *peekConn) {
	defer conn.Close()

	if s.opts.Config != nil && s.opts.Config.Stealth.Camouflage.Mode == "none" {
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(s.handshakeTimeout()))
	req, err := http.ReadRequest(conn.reader)
	_ = conn.SetReadDeadline(time.Time{})
	if err != nil {
		return
	}
	defer req.Body.Close()

	rec := httptest.NewRecorder()
	s.serveHTTPDecoy(rec, req)

	resp := rec.Result()
	defer resp.Body.Close()
	resp.Request = req
	if resp.ContentLength < 0 && len(resp.TransferEncoding) == 0 {
		resp.ContentLength = int64(rec.Body.Len())
	}
	resp.Header.Set("Server", s.serverHeader)
	resp.Header.Set("Connection", "close")
	resp.Close = true
	_ = resp.Write(conn)
}

// peekConn wraps a transport.Conn with a bufio.Reader to peek at the first byte.
type peekConn struct {
	transport.Conn
	reader *bufio.Reader
}

func newPeekConn(c transport.Conn) *peekConn {
	if existing, ok := c.(*peekConn); ok {
		return existing
	}
	if buffered, ok := c.(*transport.BufferedTransportConn); ok {
		return &peekConn{Conn: buffered.Conn, reader: buffered.Reader()}
	}
	return &peekConn{
		Conn:   c,
		reader: bufio.NewReader(c),
	}
}

func (c *peekConn) PeekFirstByte() (byte, error) {
	b, err := c.reader.Peek(1)
	if err != nil {
		return 0, err
	}
	return b[0], nil
}

func (c *peekConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

type httpCandidateCtxKey struct{}

type httpCandidateConn struct {
	*peekConn
	tlsState  tls.ConnectionState
	stateOnce sync.Once
	stateCh   chan http.ConnState
	wsCh      chan *websocket.Conn
}

func newHTTPCandidateConn(c *peekConn, tlsState tls.ConnectionState) *httpCandidateConn {
	return &httpCandidateConn{
		peekConn: c,
		tlsState: tlsState,
		stateCh:  make(chan http.ConnState, 1),
		wsCh:     make(chan *websocket.Conn, 1),
	}
}

func (c *httpCandidateConn) notifyState(state http.ConnState) {
	c.stateOnce.Do(func() {
		c.stateCh <- state
	})
}

type chanListener struct {
	conns  chan net.Conn
	closed chan struct{}
	once   sync.Once
}

func newChanListener() *chanListener {
	return &chanListener{
		conns:  make(chan net.Conn, 256),
		closed: make(chan struct{}),
	}
}

func (l *chanListener) Enqueue(ctx context.Context, c net.Conn) bool {
	select {
	case <-l.closed:
		return false
	case <-ctx.Done():
		return false
	case l.conns <- c:
		return true
	}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.conns:
		return c, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() {
		close(l.closed)
		for {
			select {
			case c := <-l.conns:
				_ = c.Close()
			default:
				return
			}
		}
	})
	return nil
}

func (l *chanListener) Addr() net.Addr {
	return &net.TCPAddr{}
}

// Start starts the session writer loop.
func (sw *SessionWriter) Start() {
	for {
		select {
		case <-sw.ctx.Done():
			return
		case f, ok := <-sw.writeQueue:
			if !ok {
				return
			}

			// Normalize inter-frame timing (a no-op when disabled). Applied
			// before padding so the on-wire schedule already resembles
			// background HTTPS traffic.
			sw.engine.ApplyJitter()

			// Apply stealth padding. Fail-closed: if CSPRNG padding cannot be
			// generated we must NOT send an unpadded frame (it would weaken
			// obfuscation and could be fingerprinted), so the frame is dropped.
			if err := stealth.ApplyPadding(f, sw.engine); err != nil {
				sw.metrics.ProtocolErrors.Add(1)
				continue
			}

			data, err := f.Encode()
			if err != nil {
				sw.metrics.ProtocolErrors.Add(1)
				continue
			}

			_, err = sw.conn.Write(data)
			if err != nil {
				return
			}

			sw.metrics.FramesSent.Add(1)
			sw.metrics.BytesSent.Add(int64(len(data)))
			buffer.DefaultPool.Put(data)
		}
	}
}

// QueueFrame adds a frame to the writer's write queue with backpressure control.
func (sw *SessionWriter) QueueFrame(f *protocol.Frame) bool {
	select {
	case sw.writeQueue <- f:
		return true
	case <-sw.ctx.Done():
		return false
	}
}

// Close gracefully closes the session writer.
func (sw *SessionWriter) Close() {
	sw.cancel()
}
