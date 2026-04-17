package handshake

import (
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultRelayIdleTimeout is the inactivity period after which an
// upstream forwarding session is closed and removed.
const DefaultRelayIdleTimeout = 30 * time.Second

// DefaultRelayBufferSize is the size of the buffer used for upstream reads.
const DefaultRelayBufferSize = 1500

// Relay performs stateless 4-tuple UDP forwarding for unauthenticated
// packets. For each unique downstream client address it opens one upstream
// socket to the configured real backend; subsequent packets from the same
// client reuse that socket. Replies from upstream are written back to the
// client through Downstream.
//
// A Relay is safe for concurrent use. Call Close to tear down all upstream
// sockets and stop the idle reaper goroutine.
type Relay struct {
	// Downstream is the server's listening socket. The relay only ever
	// calls WriteTo on it; reads are owned by the caller.
	Downstream net.PacketConn

	// IdleTimeout is how long a session may sit unused before being
	// closed. Zero means DefaultRelayIdleTimeout.
	IdleTimeout time.Duration

	// BufferSize sets the read buffer size for upstream reads. Zero means
	// DefaultRelayBufferSize.
	BufferSize int

	once     sync.Once
	mu       sync.Mutex
	sessions map[string]*relaySession
	stopCh   chan struct{}
}

type relaySession struct {
	upstream net.PacketConn
	// last is the unix-nano timestamp of the most recent packet sent or
	// received on this session. Atomic for the reaper.
	last atomic.Int64
}

func (r *Relay) init() {
	r.once.Do(func() {
		r.sessions = make(map[string]*relaySession)
		r.stopCh = make(chan struct{})
		if r.IdleTimeout <= 0 {
			r.IdleTimeout = DefaultRelayIdleTimeout
		}
		if r.BufferSize <= 0 {
			r.BufferSize = DefaultRelayBufferSize
		}
		go r.reapLoop()
	})
}

// Forward delivers packet to upstreamHost:upstreamPort and arranges for
// any reply traffic on that flow to be written back to clientAddr through
// r.Downstream. It is safe to call Forward concurrently from many
// goroutines.
//
// Forward never blocks on upstream: the upstream socket is created (or
// looked up) and the packet is written synchronously, but downstream
// replies are pumped in a background goroutine.
func (r *Relay) Forward(clientAddr net.Addr, upstreamHost string, upstreamPort uint16, packet []byte) error {
	if r.Downstream == nil {
		return errors.New("mirage: relay has no Downstream")
	}
	r.init()

	sess, err := r.getOrCreateSession(clientAddr, upstreamHost, upstreamPort)
	if err != nil {
		return err
	}

	upstreamAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(upstreamHost, strconv.Itoa(int(upstreamPort))))
	if err != nil {
		return err
	}
	if _, err := sess.upstream.WriteTo(packet, upstreamAddr); err != nil {
		return err
	}
	sess.last.Store(time.Now().UnixNano())
	return nil
}

// Close tears down every upstream session and stops the reaper. It does
// not close r.Downstream. Close is idempotent.
func (r *Relay) Close() error {
	r.init()
	select {
	case <-r.stopCh:
		return nil
	default:
	}
	close(r.stopCh)
	r.mu.Lock()
	for k, s := range r.sessions {
		_ = s.upstream.Close()
		delete(r.sessions, k)
	}
	r.mu.Unlock()
	return nil
}

func (r *Relay) getOrCreateSession(clientAddr net.Addr, upstreamHost string, upstreamPort uint16) (*relaySession, error) {
	key := clientAddr.String()

	r.mu.Lock()
	if s, ok := r.sessions[key]; ok {
		r.mu.Unlock()
		return s, nil
	}

	upstream, err := net.ListenUDP("udp", nil)
	if err != nil {
		r.mu.Unlock()
		return nil, err
	}
	s := &relaySession{upstream: upstream}
	s.last.Store(time.Now().UnixNano())
	r.sessions[key] = s
	r.mu.Unlock()

	go r.pumpUpstream(clientAddr, s)
	return s, nil
}

func (r *Relay) pumpUpstream(clientAddr net.Addr, s *relaySession) {
	buf := make([]byte, r.BufferSize)
	for {
		n, _, err := s.upstream.ReadFrom(buf)
		if err != nil {
			return
		}
		if _, err := r.Downstream.WriteTo(buf[:n], clientAddr); err != nil {
			return
		}
		s.last.Store(time.Now().UnixNano())
	}
}

func (r *Relay) reapLoop() {
	t := time.NewTicker(r.IdleTimeout / 2)
	defer t.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case now := <-t.C:
			cutoff := now.Add(-r.IdleTimeout).UnixNano()
			r.mu.Lock()
			for k, s := range r.sessions {
				if s.last.Load() < cutoff {
					_ = s.upstream.Close()
					delete(r.sessions, k)
				}
			}
			r.mu.Unlock()
		}
	}
}
