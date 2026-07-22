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
	s := c.conn.ConnectionState()
	// uTLS returns its own ConnectionState type. The transport contract only
	// needs the standard crypto/tls fields, which have identical names and
	// meanings, so we copy them across. Peer certificate chains are not used
	// by FGXP (PSK auth), so they are intentionally omitted.
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

func (c *utlsConn) TransportType() Type { return TCP }

// DialUTLS establishes a TCP connection and performs a uTLS handshake that
// mimics the chosen browser fingerprint. tlsCfg provides ServerName, trust
// roots and ALPN; it is copied into a uTLS Config because uTLS reuses the same
// shape (utls.Config embeds the standard crypto/tls Config fields).
func DialUTLS(ctx context.Context, addr string, tlsCfg *tls.Config, fingerprint string) (Conn, error) {
	if tlsCfg == nil {
		tlsCfg = &tls.Config{}
	}

	dialer := &net.Dialer{KeepAlive: 30 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}

	if tcpConn, ok := rawConn.(*net.TCPConn); ok {
		_ = tcpConn.SetNoDelay(true)
		_ = tcpConn.SetReadBuffer(4194304)  // 4MB receive buffer
		_ = tcpConn.SetWriteBuffer(4194304) // 4MB send buffer
	}

	uCfg := &utls.Config{
		ServerName:         tlsCfg.ServerName,
		InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
		RootCAs:            tlsCfg.RootCAs,
		NextProtos:         tlsCfg.NextProtos,
		MinVersion:         tlsCfg.MinVersion,
		MaxVersion:         tlsCfg.MaxVersion,
	}
	// When verification is disabled we must not also reject the (decoy) SNI
	// host; InsecureServerNameToVerify handles that for uTLS.
	if uCfg.InsecureSkipVerify {
		uCfg.InsecureServerNameToVerify = "" // already skipped via InsecureSkipVerify
	} else if uCfg.ServerName != "" {
		uCfg.InsecureServerNameToVerify = uCfg.ServerName
	}

	uConn := utls.UClient(rawConn, uCfg, resolveClientHelloID(fingerprint))

	if deadline, ok := ctx.Deadline(); ok {
		_ = uConn.SetDeadline(deadline)
	}
	if err := uConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, err
	}
	_ = uConn.SetDeadline(time.Time{})

	return &utlsConn{conn: uConn}, nil
}
