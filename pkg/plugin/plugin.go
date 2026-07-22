// Package plugin provides the FGXP plugin system.
// Plugins extend FGXP behavior through a hook-based architecture
// without modifying core protocol code.
package plugin

import (
	"context"
	"fmt"
	"sync"
)

// Plugin defines the contract for FGXP plugins.
type Plugin interface {
	// Name returns a unique identifier for this plugin.
	Name() string

	// Version returns the semantic version of this plugin.
	Version() string

	// Init is called once during server/client startup.
	Init(ctx context.Context, config map[string]any) error

	// Close is called during graceful shutdown.
	Close() error
}

// ConnInfo carries connection metadata passed to hooks.
type ConnInfo struct {
	RemoteAddr string
	LocalAddr  string
	Transport  string // "tcp" or "quic"
	SNI        string
}

// StreamInfo carries stream metadata passed to hooks.
type StreamInfo struct {
	StreamID   uint32
	StreamType string
	Priority   uint8
}

// AuthIdentity carries auth info passed to hooks.
type AuthIdentity struct {
	KeyID     []byte
	Method    string
	SessionID string
}

// AuthResult is returned by OnAuth hooks.
type AuthResult struct {
	Allow   bool
	Reason  string
}

// Hook interfaces — plugins implement only the hooks they need.

// OnConnectHook is called when a new transport connection is established.
type OnConnectHook interface {
	OnConnect(ctx context.Context, conn ConnInfo) error
}

// OnAuthHook is called during authentication.
type OnAuthHook interface {
	OnAuth(ctx context.Context, identity AuthIdentity) (AuthResult, error)
}

// OnStreamOpenHook is called when a new stream is opened.
type OnStreamOpenHook interface {
	OnStreamOpen(ctx context.Context, stream StreamInfo) error
}

// OnDataHook is called for data transformation (e.g., logging, filtering).
type OnDataHook interface {
	OnDataSend(ctx context.Context, streamID uint32, data []byte) ([]byte, error)
	OnDataRecv(ctx context.Context, streamID uint32, data []byte) ([]byte, error)
}

// OnStreamCloseHook is called when a stream is closed.
type OnStreamCloseHook interface {
	OnStreamClose(ctx context.Context, streamID uint32, err error)
}

// OnDisconnectHook is called when a session disconnects.
type OnDisconnectHook interface {
	OnDisconnect(ctx context.Context, sessionID string, err error)
}

// Registry manages registered plugins and dispatches hooks.
type Registry struct {
	mu      sync.RWMutex
	plugins []Plugin

	// Cached hook chains for fast dispatch.
	onConnect    []OnConnectHook
	onAuth       []OnAuthHook
	onStreamOpen []OnStreamOpenHook
	onData       []OnDataHook
	onStreamClose []OnStreamCloseHook
	onDisconnect []OnDisconnectHook
}

// NewRegistry creates a new plugin registry.
func NewRegistry() *Registry {
	return &Registry{}
}

// Register adds a plugin to the registry. Must be called before Init.
func (r *Registry) Register(p Plugin) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, existing := range r.plugins {
		if existing.Name() == p.Name() {
			return fmt.Errorf("fgxp/plugin: plugin %q already registered", p.Name())
		}
	}

	r.plugins = append(r.plugins, p)

	// Cache hook implementations for fast dispatch.
	if h, ok := p.(OnConnectHook); ok {
		r.onConnect = append(r.onConnect, h)
	}
	if h, ok := p.(OnAuthHook); ok {
		r.onAuth = append(r.onAuth, h)
	}
	if h, ok := p.(OnStreamOpenHook); ok {
		r.onStreamOpen = append(r.onStreamOpen, h)
	}
	if h, ok := p.(OnDataHook); ok {
		r.onData = append(r.onData, h)
	}
	if h, ok := p.(OnStreamCloseHook); ok {
		r.onStreamClose = append(r.onStreamClose, h)
	}
	if h, ok := p.(OnDisconnectHook); ok {
		r.onDisconnect = append(r.onDisconnect, h)
	}

	return nil
}

// InitAll initializes all registered plugins.
func (r *Registry) InitAll(ctx context.Context, configs map[string]map[string]any) error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, p := range r.plugins {
		cfg := configs[p.Name()]
		if err := p.Init(ctx, cfg); err != nil {
			return fmt.Errorf("fgxp/plugin: init %q: %w", p.Name(), err)
		}
	}
	return nil
}

// CloseAll shuts down all plugins in reverse order.
func (r *Registry) CloseAll() error {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for i := len(r.plugins) - 1; i >= 0; i-- {
		if err := r.plugins[i].Close(); err != nil {
			return fmt.Errorf("fgxp/plugin: close %q: %w", r.plugins[i].Name(), err)
		}
	}
	return nil
}

// RunOnConnect executes all OnConnect hooks in registration order.
func (r *Registry) RunOnConnect(ctx context.Context, conn ConnInfo) error {
	r.mu.RLock()
	hooks := r.onConnect
	r.mu.RUnlock()

	for _, h := range hooks {
		if err := h.OnConnect(ctx, conn); err != nil {
			return err
		}
	}
	return nil
}

// RunOnAuth executes all OnAuth hooks. Any hook returning Allow=false stops the chain.
func (r *Registry) RunOnAuth(ctx context.Context, identity AuthIdentity) (AuthResult, error) {
	r.mu.RLock()
	hooks := r.onAuth
	r.mu.RUnlock()

	for _, h := range hooks {
		result, err := h.OnAuth(ctx, identity)
		if err != nil {
			return AuthResult{}, err
		}
		if !result.Allow {
			return result, nil
		}
	}
	return AuthResult{Allow: true}, nil
}

// RunOnDataSend executes data hooks for outgoing data (in registration order).
func (r *Registry) RunOnDataSend(ctx context.Context, streamID uint32, data []byte) ([]byte, error) {
	r.mu.RLock()
	hooks := r.onData
	r.mu.RUnlock()

	var err error
	for _, h := range hooks {
		data, err = h.OnDataSend(ctx, streamID, data)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

// RunOnDataRecv executes data hooks for incoming data (in reverse order).
func (r *Registry) RunOnDataRecv(ctx context.Context, streamID uint32, data []byte) ([]byte, error) {
	r.mu.RLock()
	hooks := r.onData
	r.mu.RUnlock()

	var err error
	for i := len(hooks) - 1; i >= 0; i-- {
		data, err = hooks[i].OnDataRecv(ctx, streamID, data)
		if err != nil {
			return nil, err
		}
	}
	return data, nil
}

// RunOnStreamClose executes stream close hooks.
func (r *Registry) RunOnStreamClose(ctx context.Context, streamID uint32, closeErr error) {
	r.mu.RLock()
	hooks := r.onStreamClose
	r.mu.RUnlock()

	for _, h := range hooks {
		h.OnStreamClose(ctx, streamID, closeErr)
	}
}

// RunOnDisconnect executes disconnect hooks.
func (r *Registry) RunOnDisconnect(ctx context.Context, sessionID string, disconnErr error) {
	r.mu.RLock()
	hooks := r.onDisconnect
	r.mu.RUnlock()

	for _, h := range hooks {
		h.OnDisconnect(ctx, sessionID, disconnErr)
	}
}
