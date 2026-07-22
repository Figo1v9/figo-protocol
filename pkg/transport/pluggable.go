// Package transport implements Layer 1 abstractions for FGXP.
// pluggable.go provides the Stage 5 Pluggable Transport (PT) wrapper interface
// and reference implementations (e.g. ScrambleTransport) to obfuscate L1 connections.
package transport

import (
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	fgxpcrypto "github.com/figox/figox-protocol/internal/crypto"
)

// PluggableTransport defines the interface for an L1 obfuscation wrapper.
type PluggableTransport interface {
	// Name returns the identifier of the transport (e.g. "scramble", "obfs4").
	Name() string

	// WrapConn wraps a network connection with obfuscation.
	WrapConn(conn Conn) (Conn, error)
}

// Registry manages available Pluggable Transport drivers.
type Registry struct {
	mu         sync.RWMutex
	transports map[string]PluggableTransport
}

// DefaultRegistry is the global Pluggable Transport registry.
var DefaultRegistry = NewRegistry()

// NewRegistry creates a new Pluggable Transport registry.
func NewRegistry() *Registry {
	r := &Registry{
		transports: make(map[string]PluggableTransport),
	}
	// Register default scramble transport
	r.Register(&ScrambleTransport{Key: []byte("fgxp-default-scramble-key-32b!")})
	return r
}

// Register registers a PluggableTransport.
func (r *Registry) Register(pt PluggableTransport) {
	if pt == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.transports[pt.Name()] = pt
}

// Get returns the registered PluggableTransport by name.
func (r *Registry) Get(name string) (PluggableTransport, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pt, ok := r.transports[name]
	return pt, ok
}

// ScrambleTransport implements Stage 5 stream-cipher payload scrambling.
// It wraps a connection using AES-256-CTR with a key derived from a shared secret,
// turning any wire stream into high-entropy noise without recognizable patterns.
type ScrambleTransport struct {
	Key      []byte
	IsServer bool
}

func (s *ScrambleTransport) Name() string {
	return "scramble"
}

func (s *ScrambleTransport) WrapConn(conn Conn) (Conn, error) {
	if conn == nil {
		return nil, fmt.Errorf("fgxp/transport: WrapConn nil conn")
	}

	key := s.Key
	if len(key) == 0 {
		key = []byte("fgxp-default-scramble-key-32b!")
	}

	// Derive 32-byte key and 16-byte IV from secret
	hash := sha256.Sum256(key)
	cipherKey := hash[:]

	ivHash := sha256.Sum256(append(hash[:], []byte("iv-seed")...))
	c2sIV := ivHash[:16]
	s2cIV := ivHash[16:32]

	var readIV, writeIV []byte
	if s.IsServer {
		readIV = c2sIV
		writeIV = s2cIV
	} else {
		writeIV = c2sIV
		readIV = s2cIV
	}

	readStream, err := fgxpcrypto.CreateCTRStream(cipherKey, readIV)
	if err != nil {
		return nil, fmt.Errorf("fgxp/transport: create read cipher: %w", err)
	}

	writeStream, err := fgxpcrypto.CreateCTRStream(cipherKey, writeIV)
	if err != nil {
		return nil, fmt.Errorf("fgxp/transport: create write cipher: %w", err)
	}

	return &scrambleConn{
		Conn:        conn,
		readStream:  readStream,
		writeStream: writeStream,
	}, nil
}

type scrambleConn struct {
	Conn
	muRead      sync.Mutex
	muWrite     sync.Mutex
	readStream  cipher.Stream
	writeStream cipher.Stream
}

func (c *scrambleConn) Read(b []byte) (int, error) {
	c.muRead.Lock()
	defer c.muRead.Unlock()

	n, err := c.Conn.Read(b)
	if n > 0 {
		c.readStream.XORKeyStream(b[:n], b[:n])
	}
	return n, err
}

func (c *scrambleConn) Write(b []byte) (int, error) {
	c.muWrite.Lock()
	defer c.muWrite.Unlock()

	buf := make([]byte, len(b))
	c.writeStream.XORKeyStream(buf, b)
	n, err := c.Conn.Write(buf)
	if err != nil && n < len(buf) {
		return n, err
	}
	return len(b), nil
}

func (c *scrambleConn) Close() error {
	return c.Conn.Close()
}

func (c *scrambleConn) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *scrambleConn) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *scrambleConn) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *scrambleConn) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *scrambleConn) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

// netConnWrapper wraps a net.Conn with a transport.Type
type netConnWrapper struct {
	net.Conn
	transportType Type
}

func (w *netConnWrapper) ConnectionState() tls.ConnectionState {
	return tls.ConnectionState{}
}

func (w *netConnWrapper) TransportType() Type {
	return w.transportType
}

func WrapNetConn(c net.Conn, t Type) Conn {
	return &netConnWrapper{Conn: c, transportType: t}
}

// Ensure interface implementation
var _ io.ReadWriteCloser = (*scrambleConn)(nil)
