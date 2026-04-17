package handshake

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/proto"
	"github.com/valtrogen/mirage/transport"
)

var dbgLog = log.New(os.Stderr, "[mirage-srv] ", log.LstdFlags|log.Lmicroseconds)
var dbgOn = os.Getenv("MIRAGE_SERVER_DEBUG") != ""

func dbg(f string, args ...any) {
	if dbgOn {
		dbgLog.Printf(f, args...)
	}
}

// DispatchDecision is the routing outcome for one incoming datagram.
type DispatchDecision int

const (
	// DispatchDrop discards the datagram (e.g. malformed unsolicited
	// short-header packet from an unknown client).
	DispatchDrop DispatchDecision = iota
	// DispatchAuth delivers the datagram to the authenticated mirage
	// listener.
	DispatchAuth
	// DispatchRelay forwards the datagram (and any subsequent traffic
	// on the same 4-tuple) to a real backend.
	DispatchRelay
)

// SessionState holds per-client routing state.
type SessionState struct {
	Decision DispatchDecision
	UserID   adapter.UserID
	// LastSNI is recorded when the client is authenticated; it is left
	// empty for relay sessions.
	LastSNI string
	// last is the unix-nano timestamp of the most recent packet for this
	// 4-tuple. Atomic so the reaper does not contend with the read path.
	last atomic.Int64
}

// Dispatcher reads from PacketConn and routes each datagram to the auth
// listener or to the SNI relay. Routing is decided once per 4-tuple on
// the first Initial packet and then cached.
//
// A Dispatcher is single-use: call Start to spawn the read loop, Close to
// stop it. The two entry points may be called from different goroutines.
type Dispatcher struct {
	// PacketConn is the bound UDP socket.
	PacketConn net.PacketConn

	// Keyring authenticates session_id fields.
	Keyring *Keyring

	// Authenticator maps a verified short-id to an opaque user identity.
	// Required.
	Authenticator adapter.UserAuthenticator

	// SNITargets resolves SNI to a real backend host:port. If nil,
	// unauthenticated traffic is dropped instead of being forwarded.
	SNITargets adapter.SNITargetProvider

	// Relay is used to forward unauthenticated traffic. If nil and
	// SNITargets is non-nil, a Relay backed by PacketConn is created
	// on Start.
	Relay *Relay

	// SessionTTL is how long an idle 4-tuple state entry survives. Zero
	// means 5 minutes.
	SessionTTL time.Duration

	// AuthSink, if non-nil, receives full datagrams that successfully
	// authenticated. The auth listener is expected to read from this
	// channel; reads on a closed channel are interpreted as listener
	// shutdown. If nil, an internal channel is created on Start and is
	// exposed via AuthChannel().
	AuthSink chan AuthDatagram

	once     sync.Once
	stopCh   chan struct{}
	mu       sync.Mutex
	sessions map[string]*SessionState
}

// AuthDatagram is one authenticated UDP datagram together with its
// remote address. It is delivered to the auth listener through the
// dispatcher's sink channel.
type AuthDatagram struct {
	Data       []byte
	RemoteAddr net.Addr
	UserID     adapter.UserID
}

// AuthChannel returns the channel from which authenticated datagrams are
// read. When AuthSink was supplied externally, this returns that same
// channel. Safe to call before or after Start.
func (d *Dispatcher) AuthChannel() <-chan AuthDatagram {
	d.init()
	return d.AuthSink
}

// Start spawns the read loop and the idle-session reaper. It returns
// immediately; the loops run until Close is called or PacketConn is
// closed.
func (d *Dispatcher) Start() error {
	if d.PacketConn == nil {
		return errors.New("mirage: Dispatcher.PacketConn is nil")
	}
	if d.Keyring == nil {
		return errors.New("mirage: Dispatcher.Keyring is nil")
	}
	if d.Authenticator == nil {
		return errors.New("mirage: Dispatcher.Authenticator is nil")
	}
	d.init()
	if d.SNITargets != nil && d.Relay == nil {
		d.Relay = &Relay{Downstream: d.PacketConn}
	}
	go d.readLoop()
	go d.reapLoop()
	return nil
}

// Close stops the dispatcher loops and the relay. It does not close
// PacketConn; the caller owns it.
func (d *Dispatcher) Close() error {
	d.init()
	select {
	case <-d.stopCh:
		return nil
	default:
	}
	close(d.stopCh)
	if d.Relay != nil {
		_ = d.Relay.Close()
	}
	return nil
}

// SessionCount returns the number of cached 4-tuple entries. It is
// intended for tests and operational metrics.
func (d *Dispatcher) SessionCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.sessions)
}

// UserIDFor returns the authenticated UserID associated with addr, if
// any. It is used by Server to attach a user identity to each accepted
// quic.Conn. The bool result is false when addr has no cached session
// or the session is not in the auth state.
func (d *Dispatcher) UserIDFor(addr net.Addr) (adapter.UserID, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.sessions[addr.String()]
	if !ok || s.Decision != DispatchAuth {
		return adapter.UserID{}, false
	}
	return s.UserID, true
}

func (d *Dispatcher) init() {
	d.once.Do(func() {
		d.stopCh = make(chan struct{})
		d.sessions = make(map[string]*SessionState)
		if d.SessionTTL <= 0 {
			d.SessionTTL = 5 * time.Minute
		}
		if d.AuthSink == nil {
			d.AuthSink = make(chan AuthDatagram, 256)
		}
	})
}

func (d *Dispatcher) readLoop() {
	buf := make([]byte, 1500)
	for {
		select {
		case <-d.stopCh:
			return
		default:
		}
		n, addr, err := d.PacketConn.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.EOF) {
				return
			}
			continue
		}
		dg := make([]byte, n)
		copy(dg, buf[:n])
		d.dispatch(addr, dg)
	}
}

// dispatch is the core routing decision. It is exported only via the
// readLoop; tests call it directly through the Dispatch method below.
func (d *Dispatcher) dispatch(addr net.Addr, datagram []byte) {
	key := addr.String()

	d.mu.Lock()
	sess := d.sessions[key]
	d.mu.Unlock()

	if sess != nil {
		sess.last.Store(time.Now().UnixNano())
		switch sess.Decision {
		case DispatchAuth:
			dbg("dispatch(%s): cached AUTH datagram len=%d first=0x%02x", addr, len(datagram), datagram[0])
			d.deliverAuth(addr, datagram, sess.UserID)
		case DispatchRelay:
			d.deliverRelay(addr, datagram, sess.LastSNI)
		}
		return
	}

	// First packet from this 4-tuple. Try to parse as Initial.
	dec, userID, sni := d.classify(addr, datagram)
	sess = &SessionState{Decision: dec, UserID: userID, LastSNI: sni}
	sess.last.Store(time.Now().UnixNano())

	d.mu.Lock()
	if existing, ok := d.sessions[key]; ok {
		// Lost a race; honor the existing entry.
		sess = existing
	} else {
		d.sessions[key] = sess
	}
	d.mu.Unlock()

	switch sess.Decision {
	case DispatchAuth:
		d.deliverAuth(addr, datagram, sess.UserID)
	case DispatchRelay:
		d.deliverRelay(addr, datagram, sess.LastSNI)
	}
}

// classify performs the one-shot authentication on the first packet of
// a flow. It returns the routing decision and, on success, the resolved
// UserID and the SNI the relay would target if classification had
// failed (currently unused but recorded for symmetry with relay
// sessions).
func (d *Dispatcher) classify(addr net.Addr, datagram []byte) (DispatchDecision, adapter.UserID, string) {
	pkt, err := transport.ParseInitial(datagram)
	if err != nil {
		dbg("classify(%s): ParseInitial failed: %v", addr, err)
		return d.classifyAsRelay(addr, datagram)
	}

	hs, err := transport.ExtractCRYPTOData(pkt.Payload)
	if err != nil || len(hs) == 0 {
		dbg("classify(%s): ExtractCRYPTOData err=%v len=%d", addr, err, len(hs))
		return d.classifyAsRelay(addr, datagram)
	}
	sid, err := transport.ExtractClientHelloSessionID(hs)
	if err != nil || len(sid) != proto.SessionIDLen {
		dbg("classify(%s): ExtractClientHelloSessionID err=%v len=%d", addr, err, len(sid))
		return d.classifyAsRelay(addr, datagram)
	}

	shortID, _, err := d.Keyring.Verify(sid)
	if err != nil {
		dbg("classify(%s): Keyring.Verify failed: %v sid=%x", addr, err, sid)
		return d.classifyAsRelay(addr, datagram)
	}

	uid, err := d.Authenticator.Verify(context.Background(), shortID)
	if err != nil {
		dbg("classify(%s): Authenticator.Verify failed: %v", addr, err)
		return d.classifyAsRelay(addr, datagram)
	}
	dbg("classify(%s): AUTH ok uid=%x shortid=%x", addr, uid, shortID)
	return DispatchAuth, uid, ""
}

func (d *Dispatcher) classifyAsRelay(_ net.Addr, _ []byte) (DispatchDecision, adapter.UserID, string) {
	if d.SNITargets == nil || d.Relay == nil {
		return DispatchDrop, adapter.UserID{}, ""
	}
	pool := d.SNITargets.Pool()
	if len(pool) == 0 {
		return DispatchDrop, adapter.UserID{}, ""
	}
	return DispatchRelay, adapter.UserID{}, pool[0]
}

func (d *Dispatcher) deliverAuth(addr net.Addr, datagram []byte, uid adapter.UserID) {
	select {
	case d.AuthSink <- AuthDatagram{Data: datagram, RemoteAddr: addr, UserID: uid}:
	case <-d.stopCh:
	}
}

func (d *Dispatcher) deliverRelay(addr net.Addr, datagram []byte, sni string) {
	if d.Relay == nil || d.SNITargets == nil {
		return
	}
	host, port, err := d.SNITargets.ResolveRealTarget(context.Background(), sni)
	if err != nil {
		return
	}
	_ = d.Relay.Forward(addr, host, port, datagram)
}

func (d *Dispatcher) reapLoop() {
	t := time.NewTicker(d.SessionTTL / 2)
	defer t.Stop()
	for {
		select {
		case <-d.stopCh:
			return
		case now := <-t.C:
			cutoff := now.Add(-d.SessionTTL).UnixNano()
			d.mu.Lock()
			for k, s := range d.sessions {
				if s.last.Load() < cutoff {
					delete(d.sessions, k)
				}
			}
			d.mu.Unlock()
		}
	}
}
