// Package buffer provides reusable byte buffer pools to reduce GC pressure
// in the hot path of frame encoding/decoding.
package buffer

import (
	"sync"
)

// Pool is a tiered buffer pool that returns buffers of appropriate sizes
// to avoid excessive memory waste. Buffers are pooled by size class.
//
// Size classes:
//
//	small:  <= 1KB    (typical control frames)
//	medium: <= 16KB   (typical data frames, matches TLS record)
//	large:  <= 64KB   (maximum FGXP frame)
type Pool struct {
	small  sync.Pool // <= 1024
	medium sync.Pool // <= 16384
	large  sync.Pool // <= 65536
}

// DefaultPool is the global buffer pool used by the protocol implementation.
var DefaultPool = NewPool()

// NewPool creates a new tiered buffer pool.
func NewPool() *Pool {
	return &Pool{
		small: sync.Pool{
			New: func() any { return make([]byte, 0, 1024) },
		},
		medium: sync.Pool{
			New: func() any { return make([]byte, 0, 16384) },
		},
		large: sync.Pool{
			New: func() any { return make([]byte, 0, 65536) },
		},
	}
}

// Get returns a byte slice with at least the requested capacity.
// The returned slice has length 0 and capacity >= size.
// The caller MUST call Put when done with the buffer.
func (p *Pool) Get(size int) []byte {
	switch {
	case size <= 1024:
		buf := p.small.Get().([]byte)
		return buf[:0]
	case size <= 16384:
		buf := p.medium.Get().([]byte)
		return buf[:0]
	default:
		buf := p.large.Get().([]byte)
		if cap(buf) < size {
			// Rare: requested size exceeds large pool capacity.
			// Allocate a new buffer; it won't be returned to the pool.
			return make([]byte, 0, size)
		}
		return buf[:0]
	}
}

// Put returns a buffer to the pool. The buffer MUST NOT be used after
// calling Put. Passing nil is safe and does nothing.
func (p *Pool) Put(buf []byte) {
	if buf == nil {
		return
	}
	c := cap(buf)
	// Clear the slice for safety (prevent data leaks between uses).
	buf = buf[:c]
	clear(buf)
	buf = buf[:0]

	switch {
	case c <= 1024:
		p.small.Put(buf)
	case c <= 16384:
		p.medium.Put(buf)
	case c <= 65536:
		p.large.Put(buf)
	}
	// Buffers larger than 65536 are not returned to the pool to prevent
	// memory bloat from rare oversized allocations.
}

// GetFixed returns a byte slice of exactly the requested length.
// This is useful when a fixed-size buffer is needed (e.g., header reads).
func (p *Pool) GetFixed(size int) []byte {
	buf := p.Get(size)
	return buf[:size]
}
