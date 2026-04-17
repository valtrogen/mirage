package handshake

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/metrics"
	"github.com/valtrogen/mirage/proto"
	"github.com/valtrogen/mirage/transport"
)

// DefaultMaxSessions caps Dispatcher.sessions when no explicit value is
// supplied. The figure is large enough for typical loads (millions of
// short-lived flows are uncommon for a single mirage process) and small
// enough that the LRU eviction stays cheap.
const DefaultMaxSessions = 65536

// DefaultInitialRatePerSec is the per-source-IP token-bucket refill
// rate applied to AES-GCM Initial decryption. 200/s per IP allows a
// real client (which sends one Initial per connection attempt) huge
// headroom while bounding what any single attacker can extract from
// the server.
const DefaultInitialRatePerSec = 200

// DefaultInitialRateBurst is the bucket capacity. It absorbs the
// retransmissions a healthy connection may issue at startup.
const DefaultInitialRateBurst = 50

// DispatchDecision is the routing outcome for one incoming datagram.
type DispatchDecision int

const (
	// DispatchDrop discards the datagram (e.g. malformed unsolicited
	// short-header packet from an unknown client, or a flood victim).
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

	// MaxSessions caps the number of cached 4-tuple entries. When the
	// cap is reached, the least-recently-seen entry is evicted to make
	// room. Zero uses DefaultMaxSessions.
	MaxSessions int

	// InitialRatePerSec is the per-source-IP token-bucket refill rate
	// applied to AES-GCM Initial decryption. Zero uses
	// DefaultInitialRatePerSec; a negative value disables rate limiting.
	InitialRatePerSec float64

	// InitialRateBurst is the per-source-IP bucket capacity. Zero uses
	// DefaultInitialRateBurst.
	InitialRateBurst float64

	// AuthSink, if non-nil, receives full datagrams that successfully
	// authenticated. The auth listener is expected to read from this
	// channel; reads on a closed channel are interpreted as listener
	// shutdown. If nil, an internal channel is created on Start and is
	// exposed via AuthChannel().
	AuthSink chan AuthDatagram

	// Logger receives structured events. nil installs a discard logger.
	Logger *slog.Logger

	// Metrics receives instrumentation samples. nil installs metrics.Discard.
	Metrics metrics.Sink

	once     sync.Once
	stopCh   chan struct{}
	drained  atomic.Bool
	mu       sync.Mutex
	sessions *sessionLRU
	limiter  *rateLimiter

	// Metric handles cached after init() so the hot path avoids map
	// lookups on every datagram.
	mAuth          metrics.Counter
	mAuthFail      metrics.Counter
	mAuthOverflow  metrics.Counter
	mRelay         metrics.Counter
	mDrop          metrics.Counter
	mRateLimited   metrics.Counter
	mEvictions     metrics.Counter
	mSessionsGauge metrics.Gauge
	mAuthQueue     metrics.Gauge
	mLatency       metrics.Histogram
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

// Drain switches the dispatcher to drain mode: no further datagrams
// are routed to the auth sink (AuthSink callers receive nothing new),
// but established quic-go connections continue to send and receive
// directly through the underlying socket. Existing relay sessions also
// keep flowing.
//
// Drain is intended for graceful shutdown ahead of Close.
func (d *Dispatcher) Drain() {
	d.init()
	d.drained.Store(true)
}

// SessionCount returns the number of cached 4-tuple entries. It is
// intended for tests and operational metrics.
func (d *Dispatcher) SessionCount() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sessions.Len()
}

// OverflowCount returns the number of authenticated datagrams that
// were dropped because the auth sink could not accept them in time.
// It is intended for tests; production code should observe the
// dispatcher.auth_queue_overflow counter on the Metrics sink.
func (d *Dispatcher) OverflowCount() uint64 {
	d.init()
	return d.mAuthOverflow.Value()
}

// UserIDFor returns the authenticated UserID associated with addr, if
// any. It is used by Server to attach a user identity to each accepted
// quic.Conn. The bool result is false when addr has no cached session
// or the session is not in the auth state.
func (d *Dispatcher) UserIDFor(addr net.Addr) (adapter.UserID, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	s, ok := d.sessions.Get(addr.String(), false)
	if !ok || s.Decision != DispatchAuth {
		return adapter.UserID{}, false
	}
	return s.UserID, true
}

func (d *Dispatcher) init() {
	d.once.Do(func() {
		d.stopCh = make(chan struct{})
		if d.SessionTTL <= 0 {
			d.SessionTTL = 5 * time.Minute
		}
		if d.MaxSessions <= 0 {
			d.MaxSessions = DefaultMaxSessions
		}
		d.sessions = newSessionLRU(d.MaxSessions)
		if d.InitialRatePerSec == 0 {
			d.InitialRatePerSec = DefaultInitialRatePerSec
		}
		if d.InitialRateBurst == 0 {
			d.InitialRateBurst = DefaultInitialRateBurst
		}
		if d.InitialRatePerSec > 0 {
			d.limiter = newRateLimiter(d.InitialRatePerSec, d.InitialRateBurst, d.SessionTTL)
		}
		if d.AuthSink == nil {
			d.AuthSink = make(chan AuthDatagram, 256)
		}
		if d.Logger == nil {
			d.Logger = slog.New(slog.DiscardHandler)
		}
		if d.Metrics == nil {
			d.Metrics = metrics.Discard
		}
		d.mAuth = d.Metrics.Counter("dispatcher.auth_ok")
		d.mAuthFail = d.Metrics.Counter("dispatcher.auth_fail")
		d.mAuthOverflow = d.Metrics.Counter("dispatcher.auth_queue_overflow")
		d.mRelay = d.Metrics.Counter("dispatcher.relay")
		d.mDrop = d.Metrics.Counter("dispatcher.drop")
		d.mRateLimited = d.Metrics.Counter("dispatcher.rate_limited")
		d.mEvictions = d.Metrics.Counter("dispatcher.session_evictions")
		d.mSessionsGauge = d.Metrics.Gauge("dispatcher.sessions")
		d.mAuthQueue = d.Metrics.Gauge("dispatcher.auth_queue_depth")
		d.mLatency = d.Metrics.Histogram("dispatcher.classify_seconds")
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
			d.Logger.Warn("packet read failed", slog.Any("err", err))
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
	sess, ok := d.sessions.Get(key, true)
	d.mu.Unlock()

	if ok {
		sess.last.Store(time.Now().UnixNano())
		switch sess.Decision {
		case DispatchAuth:
			// Already authenticated sessions continue to flow even
			// after Drain; the operator wants existing connections to
			// finish, not be cut off mid-byte.
			d.deliverAuthAllowDrain(addr, datagram, sess.UserID)
		case DispatchRelay:
			d.deliverRelay(addr, datagram, sess.LastSNI)
		}
		return
	}

	// New 4-tuple. Refuse to spend CPU on classification once draining:
	// no new connections, authenticated or otherwise.
	if d.drained.Load() {
		d.mDrop.Add(1)
		d.Logger.Debug("dispatcher drop: drained",
			slog.String("remote", addr.String()))
		return
	}

	// First packet from this 4-tuple. Try to parse as Initial.
	start := time.Now()
	if d.limiter != nil && !d.limiter.AllowAt(addr, start) {
		d.mRateLimited.Add(1)
		d.Logger.Debug("initial rate limited",
			slog.String("remote", addr.String()))
		return
	}
	dec, userID, sni := d.classify(addr, datagram)
	d.mLatency.Observe(time.Since(start).Seconds())

	new := &SessionState{Decision: dec, UserID: userID, LastSNI: sni}
	new.last.Store(time.Now().UnixNano())

	d.mu.Lock()
	if existing, ok := d.sessions.Get(key, true); ok {
		// Lost a race; honor the existing entry.
		new = existing
	} else if evicted := d.sessions.Put(key, new); evicted != nil {
		d.mEvictions.Add(1)
	}
	size := d.sessions.Len()
	d.mu.Unlock()
	d.mSessionsGauge.Set(int64(size))

	switch new.Decision {
	case DispatchAuth:
		d.mAuth.Add(1)
		d.Logger.Debug("auth accepted",
			slog.String("remote", addr.String()),
			slog.String("user", userIDHex(new.UserID)))
		d.deliverAuthAllowDrain(addr, datagram, new.UserID)
	case DispatchRelay:
		d.mRelay.Add(1)
		d.deliverRelay(addr, datagram, new.LastSNI)
	case DispatchDrop:
		d.mDrop.Add(1)
		d.Logger.Debug("dispatcher drop: classification rejected",
			slog.String("remote", addr.String()))
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
		d.mAuthFail.Add(1)
		return d.classifyAsRelay(addr, datagram)
	}

	hs, err := transport.ExtractCRYPTOData(pkt.Payload)
	if err != nil || len(hs) == 0 {
		d.mAuthFail.Add(1)
		return d.classifyAsRelay(addr, datagram)
	}
	sid, err := transport.ExtractClientHelloSessionID(hs)
	if err != nil || len(sid) != proto.SessionIDLen {
		d.mAuthFail.Add(1)
		return d.classifyAsRelay(addr, datagram)
	}

	shortID, _, err := d.Keyring.Verify(sid)
	if err != nil {
		d.mAuthFail.Add(1)
		return d.classifyAsRelay(addr, datagram)
	}

	uid, err := d.Authenticator.Verify(context.Background(), shortID)
	if err != nil {
		d.mAuthFail.Add(1)
		return d.classifyAsRelay(addr, datagram)
	}
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

// deliverAuthAllowDrain hands datagram to the auth sink even when the
// dispatcher has been Drain()ed. New auth sessions are blocked
// upstream in dispatch(); only previously established sessions reach
// here, and they need their CONNECTION_CLOSE / final ACKs to flow so
// that the live-conn gauge actually drops.
//
// Delivery is non-blocking: if the listener cannot keep up the datagram
// is dropped and counted via dispatcher.auth_queue_overflow. Blocking
// here would stall the read loop and ripple back to all flows on the
// shared UDP socket.
func (d *Dispatcher) deliverAuthAllowDrain(addr net.Addr, datagram []byte, uid adapter.UserID) {
	dg := AuthDatagram{Data: datagram, RemoteAddr: addr, UserID: uid}
	select {
	case d.AuthSink <- dg:
		d.mAuthQueue.Set(int64(len(d.AuthSink)))
	case <-d.stopCh:
	default:
		d.mAuthOverflow.Add(1)
		d.Logger.Warn("dispatcher: auth queue overflow, dropping datagram",
			slog.String("remote", addr.String()),
			slog.Int("queue_cap", cap(d.AuthSink)))
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
	if err := d.Relay.Forward(addr, host, port, datagram); err != nil {
		d.Logger.Warn("relay forward failed",
			slog.String("remote", addr.String()),
			slog.String("sni", sni),
			slog.Any("err", err))
	}
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
			var stale []string
			d.mu.Lock()
			d.sessions.ForEach(func(k string, s *SessionState) {
				if s.last.Load() < cutoff {
					stale = append(stale, k)
				}
			})
			for _, k := range stale {
				d.sessions.Delete(k)
			}
			size := d.sessions.Len()
			d.mu.Unlock()
			d.mSessionsGauge.Set(int64(size))
		}
	}
}

// userIDHex formats a UserID into an hex string suitable for slog
// attributes. We avoid pulling fmt because slog supports stringers
// directly through slog.String.
func userIDHex(u adapter.UserID) string {
	const hex = "0123456789abcdef"
	out := make([]byte, len(u)*2)
	for i, b := range u {
		out[i*2] = hex[b>>4]
		out[i*2+1] = hex[b&0x0F]
	}
	return string(out)
}
