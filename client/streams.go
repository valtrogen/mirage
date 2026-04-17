package client

import (
	"errors"
	"sync"
)

// ErrNoStream is returned by AcceptStream after the connection closes
// and there are no more pending peer-initiated streams.
var ErrNoStream = errors.New("mirage/client: no stream available")

// streamMap tracks all live streams on a connection. Stream IDs follow
// RFC 9000 §2.1: bit 0 = server-initiated, bit 1 = unidirectional.
// We open client-initiated bidirectional streams (IDs 0, 4, 8, ...).
type streamMap struct {
	conn *Conn

	mu        sync.Mutex
	streams   map[uint64]*Stream
	nextLocal uint64
	pending   []*Stream
	pendingCh chan struct{}
	closed    bool
}

func newStreamMap(c *Conn) *streamMap {
	return &streamMap{
		conn:      c,
		streams:   make(map[uint64]*Stream),
		nextLocal: 0,
		pendingCh: make(chan struct{}, 1),
	}
}

// openLocal allocates the next client-initiated bidi stream ID and
// registers it in the map.
func (m *streamMap) openLocal() *Stream {
	m.mu.Lock()
	id := m.nextLocal
	m.nextLocal += 4
	s := newStream(m.conn, id)
	m.streams[id] = s
	m.mu.Unlock()
	return s
}

// lookupOrCreate returns the stream with id, creating it if it is the
// peer's first reference. Streams initiated by the peer are queued for
// AcceptStream.
func (m *streamMap) lookupOrCreate(id uint64) *Stream {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s, ok := m.streams[id]; ok {
		return s
	}
	s := newStream(m.conn, id)
	m.streams[id] = s
	if isServerInitiated(id) {
		m.pending = append(m.pending, s)
		select {
		case m.pendingCh <- struct{}{}:
		default:
		}
	}
	return s
}

// accept returns the next peer-initiated stream, blocking until one is
// available. It returns ErrNoStream after the connection closes.
func (m *streamMap) accept() (*Stream, error) {
	for {
		m.mu.Lock()
		if len(m.pending) > 0 {
			s := m.pending[0]
			m.pending = m.pending[1:]
			m.mu.Unlock()
			return s, nil
		}
		if m.closed {
			m.mu.Unlock()
			return nil, ErrNoStream
		}
		m.mu.Unlock()
		<-m.pendingCh
	}
}

// snapshot returns all currently live streams. Caller must not mutate
// the slice.
func (m *streamMap) snapshot() []*Stream {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Stream, 0, len(m.streams))
	for _, s := range m.streams {
		out = append(out, s)
	}
	return out
}

// shutdown fails every stream and unblocks any AcceptStream caller.
func (m *streamMap) shutdown(err error) {
	m.mu.Lock()
	m.closed = true
	streams := make([]*Stream, 0, len(m.streams))
	for _, s := range m.streams {
		streams = append(streams, s)
	}
	m.mu.Unlock()
	for _, s := range streams {
		s.closeRecvWithError(err)
		s.closeSendWithError(err)
	}
	select {
	case m.pendingCh <- struct{}{}:
	default:
	}
}

func isServerInitiated(id uint64) bool { return id&0x01 != 0 }
