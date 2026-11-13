// Package transport provides URL parsing and HTTP framing utilities for FGXP.
package transport

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

// ParsedTransportURL holds components parsed from a full transport URL
// to handle TLS SNI extraction and Layer-7 HTTP Header framing.
type ParsedTransportURL struct {
	RawURL       string
	Scheme       string // "http" or "https"
	Host         string // "hostname:port" for HTTP Host header
	Hostname     string // "hostname" strictly for TLS SNI (no port, no path)
	Port         string // "8080", "443", etc.
	PathAndQuery string // "/download?nocache=123"
	IsTLS        bool   // true if https or port 443
}

// ParseTransportURL parses a raw transport URL or hostname input.
// It handles full URLs (e.g. https://cdn.example.com:8080/path/to/res?nocache=123)
// as well as bare hostnames/SNIs (e.g. cdn.example.com).
func ParseTransportURL(raw string) (*ParsedTransportURL, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, fmt.Errorf("empty transport URL")
	}

	workURL := raw
	if !strings.Contains(workURL, "://") {
		workURL = "https://" + workURL
	}

	u, err := url.Parse(workURL)
	if err != nil {
		return nil, fmt.Errorf("invalid transport URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, fmt.Errorf("unsupported scheme: %s (must be http or https)", u.Scheme)
	}

	hostname := u.Hostname()
	if hostname == "" {
		return nil, fmt.Errorf("missing hostname in transport URL")
	}

	port := u.Port()
	if port == "" {
		if scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	hostHeader := net.JoinHostPort(hostname, port)
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		// Standard ports can omit port in Host header if desired, but retaining hostname:port is safe
		hostHeader = u.Host
	}

	pathAndQuery := u.RequestURI()
	if pathAndQuery == "" {
		pathAndQuery = "/"
	}

	return &ParsedTransportURL{
		RawURL:       raw,
		Scheme:       scheme,
		Host:         hostHeader,
		Hostname:     hostname,
		Port:         port,
		PathAndQuery: pathAndQuery,
		IsTLS:        scheme == "https",
	}, nil
}

// StripDefaultPort removes standard :80 (http) or :443 (https) from host:port
// values while preserving non-standard ports and IPv6 brackets.
func StripDefaultPort(host, scheme string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}
	h, port, err := net.SplitHostPort(host)
	if err != nil {
		return host
	}
	if port == "" || (scheme == "http" && port == "80") || (scheme == "https" && port == "443") {
		if strings.Contains(h, ":") {
			return "[" + h + "]"
		}
		return h
	}
	return host
}

// NormalizeHTTPHost selects the HTTP Host header value from override or parsed
// URL, omitting redundant default ports (:80 / :443).
func NormalizeHTTPHost(parsed *ParsedTransportURL, override string) string {
	scheme := "https"
	if parsed != nil && parsed.Scheme != "" {
		scheme = parsed.Scheme
	}
	candidate := strings.TrimSpace(override)
	if candidate == "" && parsed != nil {
		candidate = parsed.Host
	}
	return StripDefaultPort(candidate, scheme)
}
