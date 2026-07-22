package compress

import (
	"io"

	"github.com/figox/figox-protocol/pkg/protocol"
	"github.com/pierrec/lz4/v4"
)

// lz4Compressor implements Compressor using LZ4.
type lz4Compressor struct{}

func newLZ4Compressor() *lz4Compressor {
	return &lz4Compressor{}
}

func (c *lz4Compressor) Algorithm() protocol.CompressionAlgorithm {
	return protocol.CompressionLZ4
}

func (c *lz4Compressor) Compress(src []byte) ([]byte, bool) {
	if len(src) == 0 {
		return src, false
	}

	// Prepare destination buffer using Bound
	bound := lz4.CompressBlockBound(len(src))
	dst := make([]byte, bound)
	n, err := lz4.CompressBlock(src, dst, nil)
	if err != nil || n == 0 || n >= len(src) {
		// Compression didn't help or failed — return original.
		return src, false
	}
	return dst[:n], true
}

func (c *lz4Compressor) Decompress(src []byte) ([]byte, error) {
	// Decompress requires knowing the target size or a generous buffer.
	// Since we are working with blocks, we allocate a generous buffer.
	// To prevent infinite loop/allocations, we bound it.
	dst := make([]byte, len(src)*4)
	n, err := lz4.UncompressBlock(src, dst)
	if err != nil {
		return nil, err
	}
	return dst[:n], nil
}

func (c *lz4Compressor) CompressWriter(w io.Writer) io.WriteCloser {
	return lz4.NewWriter(w)
}

func (c *lz4Compressor) DecompressReader(r io.Reader) io.ReadCloser {
	return io.NopCloser(lz4.NewReader(r))
}

