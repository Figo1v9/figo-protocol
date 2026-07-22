package buffer

import (
	"testing"
)

func TestPoolGetPut(t *testing.T) {
	p := NewPool()

	// Small buffer
	buf := p.Get(100)
	if cap(buf) < 100 {
		t.Errorf("small buffer cap = %d, want >= 100", cap(buf))
	}
	if len(buf) != 0 {
		t.Errorf("small buffer len = %d, want 0", len(buf))
	}
	p.Put(buf)

	// Medium buffer
	buf = p.Get(8000)
	if cap(buf) < 8000 {
		t.Errorf("medium buffer cap = %d, want >= 8000", cap(buf))
	}
	p.Put(buf)

	// Large buffer
	buf = p.Get(32000)
	if cap(buf) < 32000 {
		t.Errorf("large buffer cap = %d, want >= 32000", cap(buf))
	}
	p.Put(buf)
}

func TestPoolGetFixed(t *testing.T) {
	p := NewPool()
	buf := p.GetFixed(16)
	if len(buf) != 16 {
		t.Errorf("GetFixed(16) len = %d, want 16", len(buf))
	}
	p.Put(buf)
}

func TestPoolPutNil(t *testing.T) {
	p := NewPool()
	p.Put(nil) // Should not panic
}

func TestPoolOversized(t *testing.T) {
	p := NewPool()
	buf := p.Get(100000) // Larger than any pool tier
	if cap(buf) < 100000 {
		t.Errorf("oversized buffer cap = %d, want >= 100000", cap(buf))
	}
	p.Put(buf) // Should not panic; buffer is not returned to pool
}

func BenchmarkPoolGetPut(b *testing.B) {
	p := NewPool()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		buf := p.Get(4096)
		p.Put(buf)
	}
}
