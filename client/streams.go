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

	// controlSink, when non-nil, captures the first server-initiated
	// bidirectional stream the dispatcher observes (the mirage
	// control stream) instead of placing it on the AcceptStream
	// queue. The integrator typically wires this in
	// configureControlStream when Config.OnRecycleHint is set.
	controlSink     chan<- *Stream
	controlConsumed bool
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
// registers it in the map. The new stream's send-side flow control
// limit is seeded from the peer's initial_max_stream_data_bidi_remote
// (RFC 9000 §18.2): the server tells us, for streams we open against
// it, how many bytes it is initially willing to receive.
// defaultSendBufCap is the maximum bytes buffered in Stream.sendBuf
// before Write blocks. This provides backpressure to fast producers
// so we don't exhaust memory when the network is slower than the app.
const defaultSendBufCap = 256 * 1024 // 256 KiB

func (m *streamMap) openLocal() *Stream {
	m.mu.Lock()
	id := m.nextLocal
	m.nextLocal += 4
	s := newStream(m.conn, id)
	if tp := m.conn.serverTP; tp != nil {
		s.sendMaxData = tp.InitialMaxStreamDataBidiRemote
	}
	// Initialize receive-side flow control from our advertised limits.
	// For client-initiated streams, we use InitialMaxStreamDataBidiLocal.
	s.recvWindow = m.conn.localInitialMaxStreamData(id)
	s.recvMaxDataAdvertised = s.recvWindow
	s.sendBufCap = defaultSendBufCap
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
	if tp := m.conn.serverTP; tp != nil {
		// For peer-initiated streams the server has authorised our
		// send side via initial_max_stream_data_bidi_local (it owns
		// the local-vs-remote naming from its perspective: we write
		// to a stream the peer initiated against us, so this is the
		// "local" direction on the peer).
		if isServerInitiated(id) {
			s.sendMaxData = tp.InitialMaxStreamDataBidiLocal
		} else {
			s.sendMaxData = tp.InitialMaxStreamDataBidiRemote
		}
	}
	// Initialize receive-side flow control from our advertised limits.
	s.recvWindow = m.conn.localInitialMaxStreamData(id)
	s.recvMaxDataAdvertised = s.recvWindow
	s.sendBufCap = defaultSendBufCap
	m.streams[id] = s
	if isServerInitiated(id) {
		// Steer the very first server-initiated bidi stream into
		// the control sink when one is registered; everything else
		// surfaces via AcceptStream as before.
		if m.controlSink != nil && !m.controlConsumed {
			m.controlConsumed = true
			select {
			case m.controlSink <- s:
			default:
			}
		} else {
			m.pending = append(m.pending, s)
			select {
			case m.pendingCh <- struct{}{}:
			default:
			}
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
