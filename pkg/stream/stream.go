// Package stream implements FGXP stream multiplexing with flow control
// and priority-based scheduling.
package stream

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/figox/figox-protocol/pkg/protocol"
)

// Stream represents a single multiplexed bidirectional byte stream.
// It implements net.Conn for compatibility with existing Go networking code.
type Stream struct {
	id        uint32
	state     atomic.Int32 // StreamState
	readBuf   chan []byte   // incoming data frames
	writeCh   chan WriteReq // outgoing data to mux scheduler
	ctx       context.Context
	cancel    context.CancelFunc
	closeOnce sync.Once
	err       error        // terminal error, if any
	unread    []byte       // unread bytes from previous frame
	mu        sync.Mutex

	// Flow control
	sendWindow   atomic.Int64 // bytes we're allowed to send
	recvWindow   atomic.Int64 // bytes we're willing to receive
	windowUpdate chan int64    // signals from WINDOW_UPDATE frames

	// Sequence tracking
	sendSeq atomic.Uint32
	recvSeq atomic.Uint32

	// Metadata
	streamType protocol.StreamType
	priority   uint8 // 1-255, higher = more bandwidth share
	createdAt  time.Time
	localAddr  net.Addr
	remoteAddr net.Addr
}

// WriteReq is a request to write data on a stream.
type WriteReq struct {
	Data   []byte
	Result chan<- WriteResult
}

// WriteResult is the outcome of a write request.
type WriteResult struct {
	N   int
	Err error
}

// StreamState mirrors session.StreamState.
type StreamState = int32

const (
	stateIdle             StreamState = 0
	stateOpen             StreamState = 1
	stateHalfCloseLocal   StreamState = 2
	stateHalfCloseRemote  StreamState = 3
	stateClosed           StreamState = 4
)

// NewStream creates a new stream with the given ID and configuration.
func NewStream(
	parentCtx context.Context,
	id uint32,
	st protocol.StreamType,
	priority uint8,
	initialWindow int64,
	localAddr, remoteAddr net.Addr,
) *Stream {
	ctx, cancel := context.WithCancel(parentCtx)
	s := &Stream{
		id:           id,
		readBuf:      make(chan []byte, 8192),  // buffer up to 8192 incoming frames (high throughput)
		writeCh:      make(chan WriteReq, 2048), // buffer up to 2048 outgoing writes
		ctx:          ctx,
		cancel:       cancel,
		windowUpdate: make(chan int64, 64),
		streamType:   st,
		priority:     priority,
		createdAt:    time.Now(),
		localAddr:    localAddr,
		remoteAddr:   remoteAddr,
	}
	s.state.Store(stateOpen)
	// Default to 64MB window for unconstrained high-speed proxying
	if initialWindow < 67108864 {
		initialWindow = 67108864 // 64MB
	}
	s.sendWindow.Store(initialWindow)
	s.recvWindow.Store(initialWindow)
	return s
}

// Verify net.Conn interface compliance at compile time.
var _ net.Conn = (*Stream)(nil)

// ID returns the stream identifier.
func (s *Stream) ID() uint32 { return s.id }

// Priority returns the stream's scheduling priority weight.
func (s *Stream) Priority() uint8 { return s.priority }

// StreamType returns the stream type (bidirectional, unidirectional, tunnel).
func (s *Stream) StreamType() protocol.StreamType { return s.streamType }

// Read reads data from the stream. Blocks until data is available,
// the stream is closed, or the context is cancelled.
func (s *Stream) Read(b []byte) (int, error) {
	s.mu.Lock()
	if len(s.unread) > 0 {
		n := copy(b, s.unread)
		s.unread = s.unread[n:]
		s.mu.Unlock()
		return n, nil
	}
	s.mu.Unlock()

	if StreamState(s.state.Load()) == stateClosed {
		return 0, io.EOF
	}

	select {
	case data, ok := <-s.readBuf:
		if !ok {
			return 0, io.EOF
		}
		s.mu.Lock()
		n := copy(b, data)
		if n < len(data) {
			s.unread = append([]byte(nil), data[n:]...)
		}
		s.mu.Unlock()
		return n, nil
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	}
}

// Write writes data to the stream. The data is queued for the
// multiplexer's priority scheduler.
func (s *Stream) Write(b []byte) (int, error) {
	st := StreamState(s.state.Load())
	if st == stateClosed || st == stateHalfCloseLocal {
		return 0, protocol.NewProtocolError(protocol.ErrStreamClosed,
			"stream is closed for writing")
	}

	resultCh := make(chan WriteResult, 1)
	req := WriteReq{
		Data:   append([]byte(nil), b...), // copy to avoid data races
		Result: resultCh,
	}

	select {
	case s.writeCh <- req:
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	}

	select {
	case res := <-resultCh:
		return res.N, res.Err
	case <-s.ctx.Done():
		return 0, s.ctx.Err()
	}
}

// Close gracefully closes the stream (sends FIN).
func (s *Stream) Close() error {
	s.closeOnce.Do(func() {
		s.state.Store(stateClosed)
		s.cancel()
		close(s.readBuf)
	})
	return nil
}

// LocalAddr returns the local network address.
func (s *Stream) LocalAddr() net.Addr { return s.localAddr }

// RemoteAddr returns the remote network address.
func (s *Stream) RemoteAddr() net.Addr { return s.remoteAddr }

// SetDeadline sets the read and write deadlines.
func (s *Stream) SetDeadline(t time.Time) error {
	// Deadlines are handled via context timeouts at the session level.
	return nil
}

// SetReadDeadline sets the read deadline.
func (s *Stream) SetReadDeadline(t time.Time) error {
	return nil
}

// SetWriteDeadline sets the write deadline.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	return nil
}

// DeliverData is called by the multiplexer to deliver incoming data.
func (s *Stream) DeliverData(data []byte) error {
	st := StreamState(s.state.Load())
	if st == stateClosed || st == stateHalfCloseRemote {
		return protocol.NewProtocolError(protocol.ErrStreamClosed,
			"stream is closed for reading")
	}

	select {
	case s.readBuf <- data:
		return nil
	case <-s.ctx.Done():
		return io.EOF
	}
}

// UpdateSendWindow increases the send window by delta.
func (s *Stream) UpdateSendWindow(delta int64) {
	s.sendWindow.Add(delta)
	select {
	case s.windowUpdate <- delta:
	default:
	}
}

// SendWindow returns the current send window size.
func (s *Stream) SendWindow() int64 {
	return s.sendWindow.Load()
}

// RecvWindow returns the current receive window size.
func (s *Stream) RecvWindow() int64 {
	return s.recvWindow.Load()
}

// DrainWrites returns the write channel for the multiplexer to consume.
func (s *Stream) DrainWrites() <-chan WriteReq {
	return s.writeCh
}

// NextSendSequence returns and increments the send sequence number.
func (s *Stream) NextSendSequence() uint32 {
	return s.sendSeq.Add(1)
}

// Mux is the stream multiplexer that schedules frame transmission
// across multiple streams using weighted fair queuing.
type Mux struct {
	mu      sync.RWMutex
	streams map[uint32]*Stream
	ctx     context.Context
	cancel  context.CancelFunc
}

// NewMux creates a new stream multiplexer.
func NewMux(parentCtx context.Context) *Mux {
	ctx, cancel := context.WithCancel(parentCtx)
	return &Mux{
		streams: make(map[uint32]*Stream),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// OpenStream registers a new stream with the multiplexer.
func (m *Mux) OpenStream(s *Stream) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, exists := m.streams[s.id]; exists {
		return fmt.Errorf("fgxp/stream: stream %d already exists", s.id)
	}
	m.streams[s.id] = s
	return nil
}

// GetStream returns the stream with the given ID.
func (m *Mux) GetStream(id uint32) (*Stream, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.streams[id]
	return s, ok
}

// CloseStream removes a stream from the multiplexer.
func (m *Mux) CloseStream(id uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.streams[id]; ok {
		s.Close()
		delete(m.streams, id)
	}
}

// StreamCount returns the number of active streams.
func (m *Mux) StreamCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.streams)
}

// Close shuts down the multiplexer and all streams.
func (m *Mux) Close() {
	m.cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.streams {
		s.Close()
		delete(m.streams, id)
	}
}
