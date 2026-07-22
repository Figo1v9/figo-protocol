// Package config handles FGXP configuration loading and hot reload.
package config

import (
	"fmt"
	"os"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// ServerConfig is the top-level server configuration.
type ServerConfig struct {
	Server      ServerSection      `yaml:"server"`
	TLS         TLSSection         `yaml:"tls"`
	Auth        AuthSection        `yaml:"auth"`
	Stealth     StealthSection     `yaml:"stealth"`
	Streams     StreamsSection     `yaml:"streams"`
	Congestion  CongestionSection  `yaml:"congestion"`
	Compression CompressionSection `yaml:"compression"`
	Limits      LimitsSection      `yaml:"limits"`
	Observability ObservabilitySection `yaml:"observability"`
	Cluster     ClusterSection     `yaml:"cluster"`
}

// ClientConfig is the top-level client configuration.
type ClientConfig struct {
	Server      ClientServerSection `yaml:"server"`
	Auth        ClientAuthSection   `yaml:"auth"`
	Stealth     StealthSection      `yaml:"stealth"`
	Streams     StreamsSection      `yaml:"streams"`
	Compression CompressionSection  `yaml:"compression"`
}

// Section types.

type ServerSection struct {
	Listen    string `yaml:"listen"`
	Transport string `yaml:"transport"` // tcp, quic, both
}

type ClientServerSection struct {
	Address   string `yaml:"address"`
	Transport string `yaml:"transport"`
	SNI       string `yaml:"sni"`
}

type TLSSection struct {
	Cert string       `yaml:"cert"`
	Key  string       `yaml:"key"`
	ACME ACMESection  `yaml:"acme"`
}

type ACMESection struct {
	Enabled bool     `yaml:"enabled"`
	Email   string   `yaml:"email"`
	Domains []string `yaml:"domains"`
}

type AuthSection struct {
	Method string       `yaml:"method"`
	Keys   []KeyConfig  `yaml:"keys"`
}

type ClientAuthSection struct {
	Method string `yaml:"method"`
	PSK    string `yaml:"psk"` // base64-encoded
	// Fingerprint selects the TLS ClientHello mimicry ("chrome", "firefox",
	// "edge", "randomized", or "none" for legacy Go stack). Defaults to
	// "chrome" when empty. See transport package for semantics.
	Fingerprint string `yaml:"fingerprint"`
}

type KeyConfig struct {
	ID      string `yaml:"id"`
	Secret  string `yaml:"secret"`  // base64-encoded
	Expires string `yaml:"expires"` // RFC3339
}

type StealthSection struct {
	Padding    PaddingSection    `yaml:"padding"`
	Timing     TimingSection     `yaml:"timing"`
	Camouflage CamouflageSection `yaml:"camouflage"`
	Pluggable  PluggableSection  `yaml:"pluggable"`
}

type PluggableSection struct {
	Enabled bool   `yaml:"enabled"`
	Name    string `yaml:"name"` // e.g. "scramble"
	Secret  string `yaml:"secret"`
}

type PaddingSection struct {
	Enabled bool   `yaml:"enabled"`
	Mode    string `yaml:"mode"`
	MinPad  int    `yaml:"min_pad"`
	MaxPad  int    `yaml:"max_pad"`
}

type TimingSection struct {
	Enabled  bool `yaml:"enabled"`
	JitterMS int  `yaml:"jitter_ms"`
}

type CamouflageSection struct {
	Mode         string `yaml:"mode"` // static, reverse_proxy
	StaticDir    string `yaml:"static_dir"`
	ProxyTarget  string `yaml:"proxy_target"`
	ServerHeader string `yaml:"server_header"`
}

type StreamsSection struct {
	MaxConcurrent int `yaml:"max_concurrent"`
	InitialWindow int `yaml:"initial_window"`
	MaxWindow     int `yaml:"max_window"`
}

type CongestionSection struct {
	Algorithm string `yaml:"algorithm"` // cubic, bbr, none
}

type CompressionSection struct {
	Algorithm string `yaml:"algorithm"` // none, lz4, zstd
}

type LimitsSection struct {
	MaxConnections    int           `yaml:"max_connections"`
	MaxStreamsPerConn  int           `yaml:"max_streams_per_conn"`
	IdleTimeout       time.Duration `yaml:"idle_timeout"`
	HandshakeTimeout  time.Duration `yaml:"handshake_timeout"`
}

type ObservabilitySection struct {
	Metrics MetricsSection `yaml:"metrics"`
	Logging LoggingSection `yaml:"logging"`
	Tracing TracingSection `yaml:"tracing"`
}

type MetricsSection struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

type LoggingSection struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type TracingSection struct {
	Enabled  bool   `yaml:"enabled"`
	Endpoint string `yaml:"endpoint"`
}

type ClusterSection struct {
	Enabled bool     `yaml:"enabled"`
	NodeID  string   `yaml:"node_id"`
	Peers   []string `yaml:"peers"`
}

// LoadServerConfig reads and parses a server configuration file.
func LoadServerConfig(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fgxp/config: read %s: %w", path, err)
	}

	cfg := &ServerConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("fgxp/config: parse %s: %w", path, err)
	}

	setServerDefaults(cfg)
	return cfg, nil
}

// LoadClientConfig reads and parses a client configuration file.
func LoadClientConfig(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("fgxp/config: read %s: %w", path, err)
	}

	cfg := &ClientConfig{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("fgxp/config: parse %s: %w", path, err)
	}

	return cfg, nil
}

// DefaultConfig returns a default ServerConfig.
func DefaultConfig() *ServerConfig {
	cfg := &ServerConfig{}
	setServerDefaults(cfg)
	return cfg
}

// setServerDefaults fills in missing configuration values.
func setServerDefaults(cfg *ServerConfig) {
	if cfg.Server.Listen == "" {
		cfg.Server.Listen = ":443"
	}
	if cfg.Server.Transport == "" {
		cfg.Server.Transport = "tcp"
	}
	if cfg.Streams.MaxConcurrent == 0 {
		cfg.Streams.MaxConcurrent = 100
	}
	if cfg.Streams.InitialWindow == 0 {
		cfg.Streams.InitialWindow = 4194304 // 4MB high-throughput flow control window
	}
	if cfg.Limits.MaxConnections == 0 {
		cfg.Limits.MaxConnections = 10000
	}
	if cfg.Limits.IdleTimeout == 0 {
		cfg.Limits.IdleTimeout = 5 * time.Minute
	}
	if cfg.Limits.HandshakeTimeout == 0 {
		cfg.Limits.HandshakeTimeout = 10 * time.Second
	}
	if cfg.Congestion.Algorithm == "" {
		cfg.Congestion.Algorithm = "cubic"
	}
	if cfg.Stealth.Camouflage.Mode == "" {
		cfg.Stealth.Camouflage.Mode = "static"
	}
	if cfg.Observability.Logging.Level == "" {
		cfg.Observability.Logging.Level = "info"
	}
	if cfg.Observability.Logging.Format == "" {
		cfg.Observability.Logging.Format = "json"
	}
}

// Watcher monitors a configuration file for changes and triggers reload.
type Watcher struct {
	mu       sync.RWMutex
	path     string
	current  *ServerConfig
	onChange func(*ServerConfig)
	stopCh   chan struct{}
}

// NewWatcher creates a configuration watcher for hot reload.
func NewWatcher(path string, initial *ServerConfig, onChange func(*ServerConfig)) *Watcher {
	return &Watcher{
		path:     path,
		current:  initial,
		onChange: onChange,
		stopCh:   make(chan struct{}),
	}
}

// Current returns the current configuration.
func (w *Watcher) Current() *ServerConfig {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.current
}

// Stop stops the watcher.
func (w *Watcher) Stop() {
	close(w.stopCh)
}

// Reload manually triggers a configuration reload.
func (w *Watcher) Reload() error {
	cfg, err := LoadServerConfig(w.path)
	if err != nil {
		return err
	}

	w.mu.Lock()
	w.current = cfg
	w.mu.Unlock()

	if w.onChange != nil {
		w.onChange(cfg)
	}
	return nil
}
