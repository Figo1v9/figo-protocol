// Package fgxp provides the public API for the FigoX Protocol (FGXP).
//
// FGXP is a stealth transport protocol that embeds multiplexed data streams
// inside standard TLS 1.3 or QUIC connections. To any network observer, FGXP
// traffic is indistinguishable from normal HTTPS/HTTP3 web traffic.
//
// # Quick Start — Client
//
//	client, err := fgxp.NewClient(fgxp.ClientOptions{
//	    ServerAddr: "example.com:443",
//	    Transport:  fgxp.TransportTCP,
//	    PSK:        []byte("shared-secret"),
//	    SNI:        "legitimate-website.com",
//	})
//	if err != nil { log.Fatal(err) }
//	defer client.Close()
//
//	stream, err := client.OpenStream(ctx)
//	if err != nil { log.Fatal(err) }
//	defer stream.Close()
//
//	stream.Write([]byte("hello"))
//
// # Quick Start — Server
//
//	server, err := fgxp.NewServer(fgxp.ServerOptions{
//	    ListenAddr: ":443",
//	    TLSCert:    "/path/to/cert.pem",
//	    TLSKey:     "/path/to/key.pem",
//	    PSK:        []byte("shared-secret"),
//	})
//	if err != nil { log.Fatal(err) }
//
//	server.OnStream(func(s fgxp.Stream) {
//	    io.Copy(targetConn, s)
//	})
//	server.ListenAndServe(ctx)
package fgxp

import (
	"github.com/figox/figox-protocol/pkg/protocol"
	"github.com/figox/figox-protocol/pkg/stealth"
	"github.com/figox/figox-protocol/pkg/transport"
)

// TransportType selects the underlying transport protocol.
type TransportType = transport.Type

const (
	// TransportTCP uses TCP with TLS 1.3.
	TransportTCP = transport.TCP

	// TransportQUIC uses the QUIC protocol with built-in TLS 1.3.
	TransportQUIC = transport.QUIC

	// TransportBoth enables listening on both TCP and QUIC (server only).
	TransportBoth = transport.Both
)

// CamouflageMode selects how the server handles non-FGXP connections.
type CamouflageMode = stealth.CamouflageMode

const (
	CamouflageNone         = stealth.CamouflageNone
	CamouflageStatic       = stealth.CamouflageStatic
	CamouflageReverseProxy = stealth.CamouflageReverseProxy
)

// CompressionType selects the compression algorithm.
type CompressionType = protocol.CompressionAlgorithm

const (
	CompressionNone = protocol.CompressionNone
	CompressionLZ4  = protocol.CompressionLZ4
	CompressionZstd = protocol.CompressionZstd
)

// Version returns the FGXP protocol version string.
func Version() string {
	return protocol.CurrentVersion.String()
}
