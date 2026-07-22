// Package client implements the FGXP client which establishes transport connections,
// performs PSK challenge-response authentication, manages multiplexed streams,
// and handles session resumption.
package client

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/figox/figox-protocol/internal/buffer"
	"github.com/figox/figox-protocol/pkg/auth"
	"github.com/figox/figox-protocol/pkg/compress"
	"github.com/figox/figox-protocol/pkg/config"
	"github.com/figox/figox-protocol/pkg/observability"
	"github.com/figox/figox-protocol/pkg/protocol"
	"github.com/figox/figox-protocol/pkg/session"
	"github.com/figox/figox-protocol/pkg/stealth"
	"github.com/figox/figox-protocol/pkg/stream"
	"github.com/figox/figox-protocol/pkg/transport"
)

// ClientOptions configures the FGXP client.
type ClientOptions struct {
	ServerAddr    string
	TransportType transport.Type
	PSK           []byte
	SNI           string
	RealIP        string // Optional target IP override for Domain Fronting and CDN routing
	InjectHost    string // Whitelisted host for HTTP Injection bypass (e.g. "digital.gov.eg")
	InjectMethod  string // Injection method: "connect", "front", "keepalive" (default: "connect")
	WSURL         string // Cloudflare Worker WebSocket relay URL (e.g. wss://my-relay.workers.dev)
	Config        *config.ClientConfig
	TLSConfig     *tls.Config

	// Fingerprint selects the TLS ClientHello mimicry used by the client to
	// evade handshake-based DPI (JA3/JA4). Supported values are defined in the
	// transport package: "chrome" (default), "firefox", "edge", "randomized".
	// "none" disables mimicry and uses the standard crypto/tls stack — this
	// leaves the recognizable "Go" fingerprint and must never be used in
	// production; it exists only for regression testing.
	Fingerprint string
}

// Client represents an FGXP client.
type Client struct {
	opts          ClientOptions
	logger        *observability.Logger
	metrics       *observability.Metrics
	authenticator *auth.PSKClientAuthenticator
	stealthEngine *stealth.Engine

	mu      sync.Mutex
	conn    transport.Conn
	session *session.Session
	mux     *stream.Mux
	writer  *SessionWriter
	ctx     context.Context
	cancel  context.CancelFunc
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

// NewClient creates a new FGXP client.
func NewClient(opts ClientOptions) (*Client, error) {
	if opts.Config == nil {
		opts.Config = &config.ClientConfig{
			Stealth: config.StealthSection{
				Padding: config.PaddingSection{
					Enabled: true,
					Mode:    "normalized",
					MinPad:  0,
					MaxPad:  255,
				},
				Timing: config.TimingSection{
					Enabled:  true,
					JitterMS: 2, // 2ms micro-jitter for high-speed throughput + stealth
				},
			},
			Streams: config.StreamsSection{
				InitialWindow: 4194304, // 4MB flow control window
			},
		}
	}

	logger := observability.NewLogger("info", "json")
	metrics := observability.NewMetrics()
	authenticator := auth.NewPSKClientAuthenticator(opts.PSK)
	stealthEngine := stealth.NewEngine(toStealthConfig(&opts.Config.Stealth))

	ctx, cancel := context.WithCancel(context.Background())

	return &Client{
		opts:          opts,
		logger:        logger,
		metrics:       metrics,
		authenticator: authenticator,
		stealthEngine: stealthEngine,
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

// Connect establishes the connection to the FGXP server and completes authentication.
func (c *Client) Connect(ctx context.Context) error {
	var parsedURL *transport.ParsedTransportURL
	sniHost := c.opts.SNI

	if c.opts.SNI != "" {
		if parsed, err := transport.ParseTransportURL(c.opts.SNI); err == nil {
			parsedURL = parsed
			sniHost = parsed.Hostname
		}
	}

	tlsCfg := c.opts.TLSConfig
	if tlsCfg == nil {
		tlsCfg = &tls.Config{
			ServerName:         sniHost,
			InsecureSkipVerify: false,
		}
	} else if tlsCfg.ServerName == "" || tlsCfg.ServerName == c.opts.SNI {
		tlsCfg.ServerName = sniHost
	}

	// Realistic ALPN so the ClientHello looks like a browser negotiating
	// HTTP/2 or HTTP/1.1. Negotiated ALPN is part of the JA4 fingerprint.
	if len(tlsCfg.NextProtos) == 0 {
		tlsCfg.NextProtos = []string{"h2", "http/1.1"}
	}

	dialAddr := c.opts.ServerAddr
	if c.opts.RealIP != "" {
		dialAddr = c.opts.RealIP
	}

	c.logger.Info("connecting to FGXP server", "addr", dialAddr, "transport", c.opts.TransportType.String(), "fingerprint", c.fingerprint(), "sni", sniHost)

	switch {
	case c.opts.WSURL != "":
		// WebSocket relay through Cloudflare Worker: bypasses ISP IP-based filtering
		c.logger.Info("WebSocket relay mode", "url", c.opts.WSURL, "inject_host", c.opts.InjectHost)
		conn, err := transport.DialWebSocket(ctx, c.opts.WSURL, c.opts.InjectHost)
		if err != nil {
			return fmt.Errorf("websocket relay failed: %w", err)
		}
		c.logger.Info("WebSocket relay connected")
		c.conn = conn
	case c.opts.InjectHost != "":
		// HTTP Injection Engine: tunnel through ISP transparent proxy
		method := transport.InjectCONNECT
		switch c.opts.InjectMethod {
		case "front":
			method = transport.InjectFrontQuery
		case "keepalive":
			method = transport.InjectKeepAlive
		}
		c.logger.Info("HTTP injection mode", "host", c.opts.InjectHost, "method", string(method), "target", dialAddr)
		rawConn, err := transport.DialWithHTTPInject(ctx, &transport.HTTPInjectConfig{
			WhitelistedHost: c.opts.InjectHost,
			TargetAddr:      dialAddr,
			Method:          method,
		})
		if err != nil {
			return fmt.Errorf("http injection failed: %w", err)
		}
		c.logger.Info("HTTP injection tunnel established", "host", c.opts.InjectHost)
		c.conn = transport.WrapRawConn(rawConn)
	case c.opts.TransportType == transport.QUIC:
		// QUIC fingerprinting is out of scope for this iteration; use the
		// standard QUIC dialer. See implementation plan §OUT OF SCOPE.
		conn, err := transport.NewQUICDialer(tlsCfg).Dial(ctx, dialAddr)
		if err != nil {
			return fmt.Errorf("transport dial quic: %w", err)
		}
		c.conn = conn
	case parsedURL != nil && !parsedURL.IsTLS:
		// Plaintext HTTP Framing mode (e.g. http://digital.gov.eg/)
		conn, err := transport.DialRawTCP(ctx, dialAddr)
		if err != nil {
			return fmt.Errorf("transport dial raw tcp: %w", err)
		}
		c.conn = conn
	case transport.IsUTLSFingerprint(c.fingerprint()):
		conn, err := transport.DialUTLS(ctx, dialAddr, tlsCfg, c.fingerprint())
		if err != nil {
			return fmt.Errorf("transport dial utls: %w", err)
		}
		c.conn = conn
	default:
		conn, err := transport.NewTCPDialer(tlsCfg, 30*time.Second).Dial(ctx, dialAddr)
		if err != nil {
			return fmt.Errorf("transport dial: %w", err)
		}
		c.conn = conn
	}

	conn := c.conn

	// If a full transport URL with path/query was specified, send HTTP Handshake framing
	if parsedURL != nil && parsedURL.PathAndQuery != "/" {
		if err := transport.SendHTTPFraming(conn, parsedURL); err != nil {
			conn.Close()
			return fmt.Errorf("http transport framing failed: %w", err)
		}
	}

	// Apply Stage 5 Pluggable Transport obfuscation wrapper if enabled
	if c.opts.Config != nil && c.opts.Config.Stealth.Pluggable.Enabled {
		ptName := c.opts.Config.Stealth.Pluggable.Name
		if ptName == "" {
			ptName = "scramble"
		}
		if ptName == "scramble" {
			st := &transport.ScrambleTransport{Key: []byte(c.opts.Config.Stealth.Pluggable.Secret), IsServer: false}
			wrapped, err := st.WrapConn(conn)
			if err != nil {
				conn.Close()
				return fmt.Errorf("pluggable transport wrap failed: %w", err)
			}
			conn = wrapped
			c.conn = conn
		}
	}

	// Authentication Handshake
	crw := &connReadWriter{conn: conn}
	authCtx, authCancel := context.WithTimeout(ctx, protocol.DefaultHandshakeTimeout)
	defer authCancel()

	authRes, err := c.authenticator.Authenticate(authCtx, crw)
	if err != nil {
		conn.Close()
		return fmt.Errorf("authentication failed: %w", err)
	}
	if !authRes.Success {
		conn.Close()
		return fmt.Errorf("authentication rejected: %s", authRes.ErrorMessage)
	}

	c.logger.Info("authenticated successfully with server", "session", fmt.Sprintf("%x", authRes.SessionID))

	c.session = session.NewSession(c.ctx)
	c.session.SetAuth(authRes.SessionID, authRes.ResumptionToken, authRes.TokenExpiry)
	_ = c.session.Transition(session.StateConnecting)
	_ = c.session.Transition(session.StateAuthenticating)
	_ = c.session.Transition(session.StateActive)

	c.mux = stream.NewMux(c.ctx)
	writerCtx, writerCancel := context.WithCancel(c.ctx)
	c.writer = &SessionWriter{
		conn:       conn,
		engine:     c.stealthEngine,
		writeQueue: make(chan *protocol.Frame, 4096),
		ctx:        writerCtx,
		cancel:     writerCancel,
		metrics:    c.metrics,
	}

	go c.writer.Start()
	go c.runReadLoop()
	go c.startKeepAliveLoop()

	return nil
}

func (c *Client) startKeepAliveLoop() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.mu.Lock()
			active := c.session != nil && c.session.IsActive() && c.writer != nil
			c.mu.Unlock()

			if active {
				pingFrame := &protocol.Frame{
					Version:  protocol.CurrentVersion,
					Type:     protocol.FramePing,
					StreamID: protocol.ControlStreamID,
					Payload:  []byte("PING"),
				}
				c.writer.QueueFrame(pingFrame)
			}
		}
	}
}

// OpenStream opens a new multiplexed stream to the server.
func (c *Client) OpenStream(ctx context.Context) (*stream.Stream, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.session == nil || !c.session.IsActive() {
		return nil, fmt.Errorf("client is not connected")
	}

	streamID := c.session.NextClientStreamID()
	priority := uint8(100) // Default priority

	// Send STREAM_OPEN frame on control stream
	openFrame := &protocol.Frame{
		Version:  protocol.CurrentVersion,
		Type:     protocol.FrameStreamOpen,
		StreamID: streamID,
		Payload:  []byte{byte(protocol.StreamTunnel), priority},
	}

	c.writer.QueueFrame(openFrame)

	st := stream.NewStream(
		c.session.Context(),
		streamID,
		protocol.StreamTunnel,
		priority,
		int64(c.opts.Config.Streams.InitialWindow),
		c.conn.LocalAddr(),
		c.conn.RemoteAddr(),
	)

	if err := c.mux.OpenStream(st); err != nil {
		return nil, err
	}

	c.metrics.TotalStreams.Add(1)
	c.metrics.ActiveStreams.Add(1)

	go c.handleStreamWrites(st)

	return st, nil
}

// Close closes the client and all active connections.
func (c *Client) Close() error {
	c.cancel()
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
	}
	if c.mux != nil {
		c.mux.Close()
	}
	if c.writer != nil {
		c.writer.Close()
	}

	return nil
}

func (c *Client) runReadLoop() {
	for {
		f, err := protocol.DecodeFrame(c.conn)
		if err != nil {
			if err != io.EOF {
				c.logger.Error("decode frame error", "error", err)
			}
			return
		}

		c.metrics.FramesReceived.Add(1)
		c.metrics.BytesReceived.Add(int64(f.TotalSize()))

		if err := f.Validate(); err != nil {
			c.logger.Warn("invalid frame received", "error", err)
			continue
		}

		c.handleFrame(f)
	}
}

func (c *Client) handleFrame(f *protocol.Frame) {
	if f.IsControl() || f.Type == protocol.FrameStreamOpen {
		c.handleControlFrame(f)
		return
	}

	st, exists := c.mux.GetStream(f.StreamID)
	if !exists {
		return
	}

	if f.Type == protocol.FrameData {
		data := f.Payload
		if f.Flags.Has(protocol.FlagCompressed) {
			alg := c.opts.Config.Compression.Algorithm
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
		if len(f.Payload) >= 8 {
			var delta int64
			for i := 0; i < 8; i++ {
				delta = (delta << 8) | int64(f.Payload[i])
			}
			st.UpdateSendWindow(delta)
		}
	}
}

func (c *Client) handleControlFrame(f *protocol.Frame) {
	switch f.Type {
	case protocol.FramePong:
		// Ping response received
	case protocol.FrameGoAway:
		c.logger.Warn("server terminated session (GOAWAY)")
		c.Close()
	}
}

func (c *Client) handleStreamWrites(st *stream.Stream) {
	defer c.mux.CloseStream(st.ID())
	defer c.metrics.ActiveStreams.Add(-1)

	for {
		select {
		case <-c.session.Context().Done():
			return
		case req, ok := <-st.DrainWrites():
			if !ok {
				return
			}

			// High-speed stream write window handling
			if st.SendWindow() < int64(len(req.Data)) {
				st.UpdateSendWindow(67108864) // Auto-replenish 64MB window headroom
			}

			var payload []byte = req.Data
			var flags protocol.Flags = 0
			alg := c.opts.Config.Compression.Algorithm
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

			c.writer.QueueFrame(frame)
			req.Result <- stream.WriteResult{N: len(req.Data), Err: nil}
		}
	}
}

// connReadWriter wraps transport.Conn to support frame-level reads/writes for auth.
// Auth frames travel through this path (bypassing the session writer) during the
// handshake, so padding must be applied here too: otherwise AUTH INIT/RESPONSE
// frames have fixed, trivially fingerprintable sizes (42/34 bytes) that survive
// on the wire and defeat the statistical evasion goal.
type connReadWriter struct {
	conn transport.Conn
}

func (crw *connReadWriter) ReadFrame() (*protocol.Frame, error) {
	return protocol.DecodeFrame(crw.conn)
}

func (crw *connReadWriter) WriteFrame(f *protocol.Frame) error {
	// Apply stealth padding to the AUTH handshake frames so their on-wire
	// size varies like real application data. DecodeFrame strips it before
	// reconstruction, so the auth logic (HMAC) is unaffected. Fail-soft:
	// if padding cannot be generated we still send — dropping AUTH here
	// would deadlock the handshake; an unpadded AUTH is a minor weakness,
	// not a protocol break.
	if err := stealth.ApplyPadding(f, stealth.NewEngine(nil)); err != nil {
		_ = err // non-fatal: frame is still encoded and sent below
	}
	_, err := f.EncodeTo(crw.conn)
	return err
}

// fingerprint returns the configured fingerprint name, defaulting to Chrome
// (browser-like) when unset. The default is deliberate: the README claims
// FGXP traffic is indistinguishable from normal HTTPS, which requires a
// browser ClientHello by default, not opt-in.
func (c *Client) fingerprint() string {
	if c.opts.Fingerprint == "" {
		return transport.FingerprintChrome
	}
	return c.opts.Fingerprint
}

type writeResult struct {
	n   int
	err error
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
