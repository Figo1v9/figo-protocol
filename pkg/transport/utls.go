// Package transport provides the Layer 1 abstraction for FGXP.
// utls.go wires a uTLS-based dialer that mimics a real browser ClientHello
// (Chrome / Firefox / Edge / randomized) so that DPI systems that fingerprint
// the handshake (JA3/JA4) cannot distinguish FGXP traffic from normal web
// browsing. uTLS is the industry-standard library used by V2Ray/Xray/Hysteria
// for exactly this purpose; crypto/tls cannot reorder extensions, inject GREASE,
// or reproduce a browser handshake, which is why the standard library alone
// leaves a "Go" fingerprint that modern censors block.
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Fingerprint presets selectable by the client. The default "chrome" parrots a
// recent Google Chrome ClientHello. "none" falls back to crypto/tls (the legacy
// Go fingerprint) — kept only for regression testing, never for production.
const (
	// FingerprintChrome mimics the latest Chrome ClientHello (GREASE, realistic
	// extension/cipher order, ALPN h2/http1.1).
	FingerprintChrome = "chrome"

	// FingerprintFirefox mimics the latest Firefox ClientHello.
	FingerprintFirefox = "firefox"

	// FingerprintEdge mimics a recent Edge ClientHello.
	FingerprintEdge = "edge"

	// FingerprintRandomized produces a fresh randomized ClientHello each run.
	FingerprintRandomized = "randomized"

	// FingerprintNone uses standard crypto/tls (Go fingerprint). NOT stealthy.
	FingerprintNone = "none"
)

// resolveClientHelloID maps a FGXP fingerprint name to a uTLS ClientHelloID.
// Unknown values fall back to Chrome to guarantee a browser-like handshake.
func resolveClientHelloID(name string) utls.ClientHelloID {
	switch name {
	case FingerprintFirefox:
		return utls.HelloFirefox_Auto
	case FingerprintEdge:
		return utls.HelloEdge_Auto
	case FingerprintRandomized:
		return utls.HelloRandomized
	case FingerprintNone:
		return utls.HelloGolang
	case FingerprintChrome, "":
		// Default — must match the README claim of "looks like normal browsing".
		return utls.HelloChrome_Auto
	default:
		return utls.HelloChrome_Auto
	}
}

// IsUTLSFingerprint reports whether the given name requires the uTLS dialer
// (i.e. it is not the legacy Go fingerprint).
func IsUTLSFingerprint(name string) bool {
	return name != FingerprintNone
}

// utlsConn adapts a *utls.UConn to the transport.Conn interface so the session
// layer above needs no knowledge of whether it is talking to crypto/tls or uTLS.
type utlsConn struct {
	conn *utls.UConn
}

var _ Conn = (*utlsConn)(nil)

func (c *utlsConn) Read(b []byte) (int, error)  { return c.conn.Read(b) }
func (c *utlsConn) Write(b []byte) (int, error) { return c.conn.Write(b) }
func (c *utlsConn) Close() error                { return c.conn.Close() }
func (c *utlsConn) LocalAddr() net.Addr         { return c.conn.LocalAddr() }
func (c *utlsConn) RemoteAddr() net.Addr        { return c.conn.RemoteAddr() }

func (c *utlsConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *utlsConn) SetReadDeadline(t time.Time) error   { return c.conn.SetReadDeadline(t) }
func (c *utlsConn) SetWriteDeadline(t time.Time) error  { return c.conn.SetWriteDeadline(t) }

func (c *utlsConn) ConnectionState() tls.ConnectionState {
	return copyUTLSConnState(c.conn.ConnectionState())
}

func (c *utlsConn) TransportType() Type { return TCP }

func copyUTLSConnState(s utls.ConnectionState) tls.ConnectionState {
	return tls.ConnectionState{
		Version:                     s.Version,
		HandshakeComplete:           s.HandshakeComplete,
		DidResume:                   s.DidResume,
		CipherSuite:                 s.CipherSuite,
		NegotiatedProtocol:          s.NegotiatedProtocol,
		NegotiatedProtocolIsMutual:  s.NegotiatedProtocolIsMutual,
		ServerName:                  s.ServerName,
		PeerCertificates:            s.PeerCertificates,
		VerifiedChains:              s.VerifiedChains,
		SignedCertificateTimestamps: s.SignedCertificateTimestamps,
		OCSPResponse:                s.OCSPResponse,
		TLSUnique:                   s.TLSUnique,
	}
}

func buildUTLSConfig(tlsCfg *tls.Config, forceHTTP1 bool) *utls.Config {
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}
	nextProtos := tlsCfg.NextProtos
	if forceHTTP1 {
		nextProtos = []string{"http/1.1"}
	}
	uCfg := &utls.Config{
		ServerName:         tlsCfg.ServerName,
		InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
		RootCAs:            tlsCfg.RootCAs,
		NextProtos:         nextProtos,
		MinVersion:         tlsCfg.MinVersion,
		MaxVersion:         tlsCfg.MaxVersion,
	}
	if uCfg.InsecureSkipVerify {
		uCfg.InsecureServerNameToVerify = ""
	} else if uCfg.ServerName != "" {
		uCfg.InsecureServerNameToVerify = uCfg.ServerName
	}
	return uCfg
}

func cloneStdTLSConfig(tlsCfg *tls.Config, forceHTTP1 bool) *tls.Config {
	var cfg *tls.Config
	if tlsCfg == nil {
		cfg = &tls.Config{}
	} else {
		cfg = tlsCfg.Clone()
	}
	if forceHTTP1 {
		cfg.NextProtos = []string{"http/1.1"}
	}
	return cfg
}

// buildHTTP1Spec clones a browser ClientHelloSpec and forces ALPN to ["http/1.1"]
// while stripping ALPS ("h2") extensions so HTTP/1.1 WebSocket upgrades remain
// compliant without falling back to the Go TLS fingerprint.
func buildHTTP1Spec(fingerprint string) (utls.ClientHelloSpec, error) {
	helloID := resolveClientHelloID(fingerprint)
	if fingerprint == FingerprintRandomized {
		helloID = utls.HelloRandomizedALPN
	}
	spec, err := utls.UTLSIdToSpec(helloID)
	if err != nil {
		return utls.ClientHelloSpec{}, fmt.Errorf("fgxp/transport: resolve utls spec %q: %w", fingerprint, err)
	}

	filtered := make([]utls.TLSExtension, 0, len(spec.Extensions)+1)
	alpnUpdated := false
	insertIdx := -1

	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *utls.ApplicationSettingsExtension, *utls.ApplicationSettingsExtensionNew:
			// Strip HTTP/2 ALPS extensions when forcing http/1.1 ALPN.
			continue
		case *utls.ALPNExtension:
			e.AlpnProtocols = []string{"http/1.1"}
			alpnUpdated = true
			filtered = append(filtered, e)
		case *utls.UtlsPaddingExtension, *utls.UtlsPreSharedKeyExtension:
			if insertIdx == -1 {
				insertIdx = len(filtered)
			}
			filtered = append(filtered, ext)
		default:
			filtered = append(filtered, ext)
		}
	}

	if !alpnUpdated {
		alpnExt := &utls.ALPNExtension{AlpnProtocols: []string{"http/1.1"}}
		if insertIdx >= 0 && insertIdx <= len(filtered) {
			filtered = append(filtered[:insertIdx], append([]utls.TLSExtension{alpnExt}, filtered[insertIdx:]...)...)
		} else {
			filtered = append(filtered, alpnExt)
		}
	}

	spec.Extensions = filtered
	return spec, nil
}

func tuneTCPSocket(rawConn net.Conn) {
	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(4194304)
		_ = tcpConn.SetWriteBuffer(4194304)
	}
}

func dialRawTLS(ctx context.Context, rawConn net.Conn, tlsCfg *tls.Config, fingerprint string, http1Only bool) (net.Conn, tls.ConnectionState, error) {
	if !IsUTLSFingerprint(fingerprint) {
		stdConn := tls.Client(rawConn, cloneStdTLSConfig(tlsCfg, http1Only))
		if deadline, ok := ctx.Deadline(); ok {
			_ = stdConn.SetDeadline(deadline)
		}
		if err := stdConn.HandshakeContext(ctx); err != nil {
			rawConn.Close()
			return nil, tls.ConnectionState{}, err
		}
		_ = stdConn.SetDeadline(time.Time{})
		return stdConn, stdConn.ConnectionState(), nil
	}

	uCfg := buildUTLSConfig(tlsCfg, http1Only)
	var uConn *utls.UConn
	if http1Only {
		spec, err := buildHTTP1Spec(fingerprint)
		if err != nil {
			rawConn.Close()
			return nil, tls.ConnectionState{}, err
		}
		uConn = utls.UClient(rawConn, uCfg, utls.HelloCustom)
		if err := uConn.ApplyPreset(&spec); err != nil {
			rawConn.Close()
			return nil, tls.ConnectionState{}, err
		}
	} else {
		uConn = utls.UClient(rawConn, uCfg, resolveClientHelloID(fingerprint))
	}

	if deadline, ok := ctx.Deadline(); ok {
		_ = uConn.SetDeadline(deadline)
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, tls.ConnectionState{}, err
	}
	_ = uConn.SetDeadline(time.Time{})

	return uConn, copyUTLSConnState(uConn.ConnectionState()), nil
}

// DialUTLS establishes a TCP connection and performs a uTLS handshake that
// mimics the chosen browser fingerprint.
func DialUTLS(ctx context.Context, addr string, tlsCfg *tls.Config, fingerprint string) (Conn, error) {
	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	tuneTCPSocket(rawConn)

	tlsConn, _, err := dialRawTLS(ctx, rawConn, tlsCfg, fingerprint, false)
	if err != nil {
		return nil, err
	}
	return wrapTLSNetConn(tlsConn), nil
}

// DialUTLSOverConn layers a uTLS (or standard TLS when fingerprint=="none")
// handshake on top of an already-established net.Conn (e.g. an HTTP CONNECT tunnel).
func DialUTLSOverConn(ctx context.Context, rawConn net.Conn, tlsCfg *tls.Config, fingerprint string) (Conn, error) {
	tlsConn, _, err := dialRawTLS(ctx, rawConn, tlsCfg, fingerprint, false)
	if err != nil {
		return nil, err
	}
	return wrapTLSNetConn(tlsConn), nil
}

// DialUTLSHTTP1 dials addr over TCP and performs a uTLS handshake restricted to
// HTTP/1.1 ALPN so WebSocket clients keep browser JA3/JA4 mimicry.
func DialUTLSHTTP1(ctx context.Context, addr string, tlsCfg *tls.Config, fingerprint string) (net.Conn, tls.ConnectionState, error) {
	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, tls.ConnectionState{}, err
	}
	tuneTCPSocket(rawConn)

	return dialRawTLS(ctx, rawConn, tlsCfg, fingerprint, true)
}

func wrapTLSNetConn(c net.Conn) Conn {
	switch typed := c.(type) {
	case *utls.UConn:
		return &utlsConn{conn: typed}
	case *tls.Conn:
		return &tcpConn{conn: typed}
	default:
		return WrapRawConn(c)
	}
}
