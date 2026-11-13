// Package server implements the FGXP server which accepts transport connections,
// handles active prober camouflage fallback, authenticates clients, and manages
// multiplexed sessions and streams.
package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
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
	stealthEngine := stealth.NewEngine(toStealthConfig(&opts.Config.Stealth))

	ctx, cancel := context.WithCancel(context.Background())

	return &Server{
		opts:          opts,
		logger:        logger,
		metrics:       metrics,
		plugins:       plugins,
		pskStore:      pskStore,
		authenticator: authenticator,
		stealthEngine: stealthEngine,
		sessions:      make(map[string]*SessionContext),
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

func toStealthConfig(cfg *config.StealthSection) *stealth.Config {
	mode := stealth.CamouflageStatic
	if cfg.Camouflage.Mode == "reverse_proxy" {
		mode = stealth.CamouflageReverseProxy
	} else if cfg.Camouflage.Mode == "none" {
		mode = stealth.CamouflageNone
	}

	return &stealth.Config{
		Padding: stealth.PaddingConfig{
			Enabled: cfg.Padding.Enabled,
			Mode:    cfg.Padding.Mode,
			MinPad:  cfg.Padding.MinPad,
			MaxPad:  cfg.Padding.MaxPad,
		},
		Timing: stealth.TimingConfig{
			Enabled:   cfg.Timing.Enabled,
			MaxJitter: time.Duration(cfg.Timing.JitterMS) * time.Millisecond,
		},
		Camouflage: stealth.CamouflageConfig{
			Mode:         mode,
			StaticDir:    cfg.Camouflage.StaticDir,
			ProxyTarget:  cfg.Camouflage.ProxyTarget,
			ServerHeader: cfg.Camouflage.ServerHeader,
		},
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

	// Listen on TCP
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
			s.logger.Info("Listening on TCP+TLS", "addr", s.opts.ListenAddr)
		} else {
			s.logger.Info("Listening on Raw TCP (HTTP Framing)", "addr", s.opts.ListenAddr)
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

// Close stops the server and closes all listeners and active sessions.
func (s *Server) Close() error {
	s.cancel()

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
	if s.opts.NoTLS {
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

	// Apply Stage 5 Pluggable Transport obfuscation wrapper if enabled
	if s.opts.Config != nil && s.opts.Config.Stealth.Pluggable.Enabled {
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

	// Check for L7 HTTP Handshake Framing (e.g. GET /download?... HTTP/1.1)
	if framedConn, err := transport.HandleHTTPFramingServer(conn); err == nil && framedConn != nil {
		conn = framedConn
	}

	// If TCP, perform active probe resistance. A legitimate FGXP client
	// starts the TLS handshake immediately; a passive/active DPI probe that
	// opens a TCP connection but never starts a recognizable TLS ClientHello
	// (or sends a plaintext HTTP probe) must be routed to camouflage and
	// never reveals any FGXP behavior.
	if conn.TransportType() == transport.TCP {
		peekable := newPeekConn(conn)
		firstByte, err := peekable.PeekFirstByte()
		if err != nil {
			// No data arrived in time, or the connection was a bare TCP
			// probe. Fail-closed: do not proceed with FGXP handling.
			s.logger.Debug("no recognizable first byte; closing as probe", "error", err)
			conn.Close()
			return
		}

		if !auth.IsFirstByteFGXP(firstByte) {
			s.logger.Info("non-FGXP traffic detected, routing to camouflage server", "remote", conn.RemoteAddr().String())
			s.handleCamouflage(peekable)
			return
		}

		conn = peekable
	}

	// Step 1: Authenticate the connection. If the handshake/authentication
	// fails for any reason, the connection is closed immediately without
	// emitting FGXP-specific framing toward a potential prober.
	crw := &connReadWriter{conn: conn}
	authCtx, authCancel := context.WithTimeout(s.ctx, protocol.DefaultHandshakeTimeout)
	defer authCancel()

	authRes, err := s.authenticator.Authenticate(authCtx, crw)
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

func (s *Server) handleCamouflage(conn *peekConn) {
	defer conn.Close()

	cfg := &s.opts.Config.Stealth.Camouflage
	if cfg.Mode == "reverse_proxy" && cfg.ProxyTarget != "" {
		targetURL, err := url.Parse(cfg.ProxyTarget)
		if err != nil {
			s.logger.Error("invalid camouflage proxy target", "url", cfg.ProxyTarget, "error", err)
			s.serveStaticCamouflage(conn)
			return
		}

		req, err := http.ReadRequest(conn.reader)
		if err != nil {
			return
		}
		defer req.Body.Close()

		req.RequestURI = ""
		req.URL.Scheme = targetURL.Scheme
		req.URL.Host = targetURL.Host
		if req.URL.Scheme == "" {
			req.URL.Scheme = "http"
		}
		req.Host = targetURL.Host
		req.Header.Set("Host", targetURL.Host)

		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: 10 * time.Second,
		}

		resp, err := client.Do(req)
		if err != nil {
			s.logger.Error("camouflage proxy request failed", "error", err)
			return
		}
		defer resp.Body.Close()

		serverHeader := cfg.ServerHeader
		if serverHeader == "" {
			serverHeader = "nginx/1.25.3"
		}
		resp.Header.Set("Server", serverHeader)
		resp.Header.Set("Connection", "close")
		resp.Close = true

		_ = resp.Write(conn)
		return
	}

	s.serveStaticCamouflage(conn)
}

func (s *Server) serveStaticCamouflage(conn net.Conn) {
	cfg := &s.opts.Config.Stealth.Camouflage
	serverHeader := cfg.ServerHeader
	if serverHeader == "" {
		serverHeader = "nginx/1.25.3"
	}

	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	defer req.Body.Close()

	html := `<!DOCTYPE html>
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
</html>`

	resp := &http.Response{
		StatusCode:    http.StatusOK,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:         make(http.Header),
		Body:          io.NopCloser(bytes.NewReader([]byte(html))),
		ContentLength: int64(len(html)),
	}
	resp.Header.Set("Server", serverHeader)
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Connection", "close")

	_ = resp.Write(conn)
}

// peekConn wraps a net.Conn with a bufio.Reader to peek at the first byte.
type peekConn struct {
	transport.Conn
	reader *bufio.Reader
}

func newPeekConn(c transport.Conn) *peekConn {
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

// singleConnListener wraps a net.Conn to implement net.Listener for a single request.
type singleConnListener struct {
	conn net.Conn
	once sync.Once
}

func (s *singleConnListener) Accept() (net.Conn, error) {
	var c net.Conn
	s.once.Do(func() {
		c = s.conn
	})
	if c == nil {
		return nil, io.EOF
	}
	return c, nil
}

func (s *singleConnListener) Close() error   { return nil }
func (s *singleConnListener) Addr() net.Addr { return s.conn.LocalAddr() }

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
