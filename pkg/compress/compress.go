// Package compress provides optional compression for FGXP data frames.
package compress

import (
	"fmt"
	"io"

	"github.com/figox/figox-protocol/pkg/protocol"
)

// Compressor compresses and decompresses data.
type Compressor interface {
	// Algorithm returns the compression algorithm identifier.
	Algorithm() protocol.CompressionAlgorithm

	// Compress compresses src and returns the compressed data.
	// If compression would increase the size, returns src unchanged and false.
	Compress(src []byte) (dst []byte, compressed bool)

	// Decompress decompresses src and returns the original data.
	Decompress(src []byte) ([]byte, error)

	// CompressWriter returns a writer that compresses data to w.
	CompressWriter(w io.Writer) io.WriteCloser

	// DecompressReader returns a reader that decompresses data from r.
	DecompressReader(r io.Reader) io.ReadCloser
}

// NoneCompressor is a no-op compressor (compression disabled).
type NoneCompressor struct{}

func (NoneCompressor) Algorithm() protocol.CompressionAlgorithm { return protocol.CompressionNone }
func (NoneCompressor) Compress(src []byte) ([]byte, bool)       { return src, false }
func (NoneCompressor) Decompress(src []byte) ([]byte, error)    { return src, nil }
func (NoneCompressor) CompressWriter(w io.Writer) io.WriteCloser {
	return &nopWriteCloser{w}
}
func (NoneCompressor) DecompressReader(r io.Reader) io.ReadCloser {
	return io.NopCloser(r)
}

type nopWriteCloser struct{ io.Writer }

func (w *nopWriteCloser) Close() error { return nil }

// New creates a compressor for the given algorithm.
func New(alg protocol.CompressionAlgorithm) (Compressor, error) {
	switch alg {
	case protocol.CompressionNone:
		return NoneCompressor{}, nil
	case protocol.CompressionLZ4:
		return newLZ4Compressor(), nil
	case protocol.CompressionZstd:
		return newZstdCompressor(), nil
	default:
		return nil, fmt.Errorf("fgxp/compress: unknown algorithm %d", alg)
	}
}
