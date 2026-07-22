package compress

import (
	"io"

	"github.com/figox/figox-protocol/pkg/protocol"
	"github.com/klauspost/compress/zstd"
)

// zstdCompressor implements Compressor using Zstandard.
type zstdCompressor struct {
	encoder *zstd.Encoder
	decoder *zstd.Decoder
}

func newZstdCompressor() *zstdCompressor {
	enc, _ := zstd.NewWriter(nil, zstd.WithEncoderLevel(zstd.SpeedDefault))
	dec, _ := zstd.NewReader(nil)
	return &zstdCompressor{encoder: enc, decoder: dec}
}

func (c *zstdCompressor) Algorithm() protocol.CompressionAlgorithm {
	return protocol.CompressionZstd
}

func (c *zstdCompressor) Compress(src []byte) ([]byte, bool) {
	if len(src) == 0 {
		return src, false
	}
	dst := c.encoder.EncodeAll(src, nil)
	if len(dst) >= len(src) {
		return src, false
	}
	return dst, true
}

func (c *zstdCompressor) Decompress(src []byte) ([]byte, error) {
	return c.decoder.DecodeAll(src, nil)
}

func (c *zstdCompressor) CompressWriter(w io.Writer) io.WriteCloser {
	enc, _ := zstd.NewWriter(w)
	return enc
}

func (c *zstdCompressor) DecompressReader(r io.Reader) io.ReadCloser {
	dec, _ := zstd.NewReader(r)
	return dec.IOReadCloser()
}
