package transport

import (
	"testing"
)

func TestParseTransportURL(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantHostname string
		wantHost     string
		wantPath     string
		wantIsTLS    bool
	}{
		{
			name:         "Full HTTPS URL with port, path and query",
			input:        "https://speedtest8.example.com:8080/download?nocache=e67ec7c5&size=25000000",
			wantHostname: "speedtest8.example.com",
			wantHost:     "speedtest8.example.com:8080",
			wantPath:     "/download?nocache=e67ec7c5&size=25000000",
			wantIsTLS:    true,
		},
		{
			name:         "Standard HTTPS domain without path",
			input:        "example.com",
			wantHostname: "example.com",
			wantHost:     "example.com",
			wantPath:     "/",
			wantIsTLS:    true,
		},
		{
			name:         "HTTP URL with path",
			input:        "http://myhost.org:80/api/v1/stream",
			wantHostname: "myhost.org",
			wantHost:     "myhost.org:80",
			wantPath:     "/api/v1/stream",
			wantIsTLS:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := ParseTransportURL(tt.input)
			if err != nil {
				t.Fatalf("ParseTransportURL(%q) unexpected error: %v", tt.input, err)
			}
			if res.Hostname != tt.wantHostname {
				t.Errorf("Hostname = %q, want %q", res.Hostname, tt.wantHostname)
			}
			if res.Host != tt.wantHost {
				t.Errorf("Host = %q, want %q", res.Host, tt.wantHost)
			}
			if res.PathAndQuery != tt.wantPath {
				t.Errorf("PathAndQuery = %q, want %q", res.PathAndQuery, tt.wantPath)
			}
			if res.IsTLS != tt.wantIsTLS {
				t.Errorf("IsTLS = %v, want %v", res.IsTLS, tt.wantIsTLS)
			}
		})
	}
}
