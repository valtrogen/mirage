package handshake

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/behavior"
	"github.com/valtrogen/mirage/metrics"
	"github.com/valtrogen/mirage/recycle"
)

// Server is a complete mirage server. It owns a UDP socket, runs the
// dispatcher, hands authenticated datagrams to a quic-go listener, and
// transparently forwards everything else to the configured SNI pool.
//
// A Server must be configured fully before Start is called and is not
// reconfigurable afterwards.
type Server struct {
	// PacketConn is the bound UDP listening socket. Required.
	PacketConn net.PacketConn

	// TLSConfig is the TLS configuration handed to quic-go. It must
	// include at least one certificate matching the SNI strings exposed
	// to authenticated clients. Required.
	TLSConfig *tls.Config

	// QUICConfig is the underlying QUIC configuration. If nil, mirage
	// installs a quic.Config aligned with behavior.Default(); otherwise
	// only the fields the caller left at their zero value are filled in.
	// See behavior.ApplyToQUICConfig for the exact mapping.
	QUICConfig *quic.Config

	// Behavior is the Chrome HTTP/3 alignment profile applied to
	// QUICConfig before quic-go starts listening. The zero value uses
	// behavior.Default().
	//
	// Operators who deliberately want to drift from the Chrome profile
	// (for instance, on a testbed) should override individual fields on
	// QUICConfig before calling Start; explicit non-zero values win.
	Behavior behavior.ChromeH3

	// MasterKey is the 32-byte mirage master key used to derive
	// time-window AEAD keys. Required. This is the *primary* key:
	// the only one a server uses for fresh outbound material.
	MasterKey []byte

	// AdditionalMasterKeys are accepted-but-not-emitted master keys.
	// During a key rotation the operator can list the previous (or
	// soon-to-be-current) key here so existing clients keep
	// authenticating while they roll over. Each entry must be 32
	// bytes. See RotateMasterKeys for runtime updates after Start.
	AdditionalMasterKeys [][]byte

	// Authenticator resolves a verified short-id to a user identity.
	// Required.
	Authenticator adapter.UserAuthenticator

	// SNITargets supplies the relay pool. If nil, unauthenticated
	// traffic is dropped instead of being forwarded.
	SNITargets adapter.SNITargetProvider

	// SessionTTL bounds dispatcher 4-tuple state. Zero uses the
	// dispatcher default (5 minutes).
	SessionTTL time.Duration

	// MaxSessions bounds the dispatcher's 4-tuple cache. Zero uses the
	// dispatcher default.
	MaxSessions int

	// InitialRatePerSec is the per-source-IP token-bucket refill rate
	// applied to AES-GCM Initial decryption. Zero uses the dispatcher
	// default; a negative value disables rate limiting.
	InitialRatePerSec float64

	// InitialRateBurst is the per-source-IP bucket capacity. Zero uses
	// the dispatcher default.
	InitialRateBurst float64

	// Logger receives structured events from the server, the dispatcher,
	// and the relay. nil installs a discard logger.
	Logger *slog.Logger

	// Metrics receives instrumentation samples. nil installs metrics.Discard.
	Metrics metrics.Sink

	// RecycleBounds configures per-connection age/byte thresholds for
	// automatic CONNECTION_RECYCLE_HINT generation. Zero (the default)
	// disables recycling entirely. When set, each accepted connection
	// receives a Tracker sampled from these bounds; the caller (typically
	// proxy.Server) tracks bytes and decides when to send the hint.
	RecycleBounds recycle.Bounds

	// AuthQueueDepth bounds the channel that hands authenticated
	// datagrams to the embedded quic-go listener. Zero uses
	// DefaultAuthQueueDepth. Tune this up for high-fanout deployments
	// where many flows can simultaneously stall on the listener side.
	AuthQueueDepth int

	dispatcher  *Dispatcher
	vpc         *virtualPacketConn
	transport   *quic.Transport
	listener    *quic.Listener
	keyring     *Keyring
	started     atomic.Bool
	conns       sync.WaitGroup
	mLiveConns  metrics.Gauge
	mAcceptOK   metrics.Counter
	mAcceptFail metrics.Counter
}

// RotateMasterKeys atomically swaps the running server's master key
// set. primary becomes the new active key; extras are accepted-but-
// not-emitted secondary keys (typically the previous primary, kept
// alive long enough for clients to roll over).
//
// Safe to call from any goroutine after Start. Returns an error if
// any key is the wrong length or the server has not been started yet.
func (s *Server) RotateMasterKeys(primary []byte, extras ...[]byte) error {
	if !s.started.Load() || s.keyring == nil {
		return errors.New("mirage: Server.RotateMasterKeys before Start")
	}
	return s.keyring.RotateKeys(primary, extras...)
}

// DefaultAuthQueueDepth is the default capacity of the channel that
// hands authenticated datagrams to the quic-go listener. 4096 absorbs
// the bursts produced by a healthy mirage client uploading at line
// rate (where one OpenStream can immediately spawn dozens of
// MTU-sized packets) without blocking the dispatcher's read loop.
// At ~1500 bytes per datagram the queue tops out at ~6 MiB, which is
// negligible for a server process.
const DefaultAuthQueueDepth = 4096

// Conn is an accepted mirage QUIC connection together with the user
// identity that authenticated it.
type Conn struct {
	*quic.Conn
	UserID adapter.UserID

	// Tracker is the per-connection recycle tracker. It is non-nil only
	// when the server is configured with non-zero RecycleBounds. The
	// caller (typically proxy.Server) should call Tracker.AddBytes as
	// traffic flows and check Tracker.Reached to know when to send the
	// CONNECTION_RECYCLE_HINT frame.
	Tracker *recycle.Tracker
}

// Start initialises the server, the dispatcher, and the quic-go listener.
// It returns immediately; the read loops continue until Close is called
// or the underlying socket fails.
func (s *Server) Start() error {
	if !s.started.CompareAndSwap(false, true) {
		return errors.New("mirage: Server.Start called twice")
	}
	if s.PacketConn == nil {
		return errors.New("mirage: Server.PacketConn is nil")
	}
	if s.TLSConfig == nil {
		return errors.New("mirage: Server.TLSConfig is nil")
	}
	if len(s.MasterKey) != 32 {
		return errors.New("mirage: Server.MasterKey must be 32 bytes")
	}
	if s.Authenticator == nil {
		return errors.New("mirage: Server.Authenticator is nil")
	}

	keyring, err := NewKeyringSet(s.MasterKey, s.AdditionalMasterKeys...)
	if err != nil {
		return err
	}
	s.keyring = keyring

	if s.Logger == nil {
		s.Logger = slog.New(slog.DiscardHandler)
	}
	if s.Metrics == nil {
		s.Metrics = metrics.Discard
	}
	s.mLiveConns = s.Metrics.Gauge("server.live_connections")
	s.mAcceptOK = s.Metrics.Counter("server.accept_ok")
	s.mAcceptFail = s.Metrics.Counter("server.accept_fail")

	depth := s.AuthQueueDepth
	if depth <= 0 {
		depth = DefaultAuthQueueDepth
	}
	authCh := make(chan AuthDatagram, depth)
	s.vpc = newVirtualPacketConn(s.PacketConn, authCh)
	s.dispatcher = &Dispatcher{
		PacketConn:        s.PacketConn,
		Keyring:           keyring,
		Authenticator:     s.Authenticator,
		SNITargets:        s.SNITargets,
		SessionTTL:        s.SessionTTL,
		MaxSessions:       s.MaxSessions,
		InitialRatePerSec: s.InitialRatePerSec,
		InitialRateBurst:  s.InitialRateBurst,
		AuthSink:          authCh,
		Logger:            s.Logger.With(slog.String("component", "dispatcher")),
		Metrics:           s.Metrics,
	}
	if err := s.dispatcher.Start(); err != nil {
		return err
	}

	s.transport = &quic.Transport{Conn: s.vpc}
	bh := s.Behavior
	if bh.IsZero() {
		bh = behavior.Default()
	}
	if s.QUICConfig == nil {
		s.QUICConfig = &quic.Config{}
	}
	behavior.ApplyToQUICConfig(s.QUICConfig, bh)
	listener, err := s.transport.Listen(s.TLSConfig, s.QUICConfig)
	if err != nil {
		_ = s.dispatcher.Close()
		return err
	}
	s.listener = listener
	return nil
}

// Accept blocks until a quic-go connection is accepted, then returns it
// together with the user identity recorded by the dispatcher.
//
// The returned connection is tracked by the server: its lifetime is
// observed via the live-connections gauge, and a Drain call will wait
// for it to terminate before returning.
func (s *Server) Accept(ctx context.Context) (*Conn, error) {
	if s.listener == nil {
		return nil, errors.New("mirage: Server not started")
	}
	c, err := s.listener.Accept(ctx)
	if err != nil {
		s.mAcceptFail.Add(1)
		return nil, err
	}
	uid, _ := s.dispatcher.UserIDFor(c.RemoteAddr())
	s.mAcceptOK.Add(1)
	s.mLiveConns.Add(1)
	s.conns.Add(1)
	go func() {
		<-c.Context().Done()
		s.mLiveConns.Add(-1)
		s.conns.Done()
	}()

	conn := &Conn{Conn: c, UserID: uid}
	if s.RecycleBounds != (recycle.Bounds{}) {
		th, _ := s.RecycleBounds.Sample(nil)
		conn.Tracker = recycle.NewTracker(th)
	}
	return conn, nil
}

// Drain stops accepting new connections and waits for currently
// accepted ones to terminate (or for ctx to expire). It does not close
// the underlying listener — the caller invokes Close after Drain
// returns.
//
// Drain is the operations primitive for SIGTERM-style rollouts: stop
// new traffic, let in-flight requests finish, then tear down.
func (s *Server) Drain(ctx context.Context) error {
	if s.listener == nil {
		return errors.New("mirage: Server not started")
	}
	if s.dispatcher != nil {
		s.dispatcher.Drain()
	}
	_ = s.listener.Close()
	done := make(chan struct{})
	go func() {
		s.conns.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close stops the listener, the dispatcher, and the virtual packet
// conn. It does not close PacketConn; the caller owns it.
//
// Order matters: the virtual packet conn must be closed first so that
// quic-go's Transport read loop unblocks, otherwise Transport.Close
// would deadlock waiting on a goroutine parked in vpc.ReadFrom.
//
// Close is hard shutdown: in-flight connections are torn down without
// grace. Use Drain first if a graceful rollout is needed.
func (s *Server) Close() error {
	if s.vpc != nil {
		_ = s.vpc.Close()
	}
	if s.listener != nil {
		_ = s.listener.Close()
	}
	if s.transport != nil {
		_ = s.transport.Close()
	}
	if s.dispatcher != nil {
		_ = s.dispatcher.Close()
	}
	return nil
}

// virtualPacketConn implements net.PacketConn by reading authenticated
// datagrams from a channel and writing back through the underlying
// real socket. It is consumed by quic-go's Transport.
type virtualPacketConn struct {
	parent   net.PacketConn
	in       chan AuthDatagram
	closeMu  sync.Mutex
	closed   chan struct{}
	deadline atomic.Pointer[time.Time]
}

func newVirtualPacketConn(parent net.PacketConn, in chan AuthDatagram) *virtualPacketConn {
	return &virtualPacketConn{
		parent: parent,
		in:     in,
		closed: make(chan struct{}),
	}
}

func (v *virtualPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	var timer *time.Timer
	var timeout <-chan time.Time
	if dl := v.deadline.Load(); dl != nil && !dl.IsZero() {
		d := time.Until(*dl)
		if d <= 0 {
			return 0, nil, &timeoutError{}
		}
		timer = time.NewTimer(d)
		defer timer.Stop()
		timeout = timer.C
	}

	select {
	case dg, ok := <-v.in:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, dg.Data)
		return n, dg.RemoteAddr, nil
	case <-v.closed:
		return 0, nil, net.ErrClosed
	case <-timeout:
		return 0, nil, &timeoutError{}
	}
}

func (v *virtualPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	return v.parent.WriteTo(p, addr)
}

func (v *virtualPacketConn) LocalAddr() net.Addr { return v.parent.LocalAddr() }

func (v *virtualPacketConn) Close() error {
	v.closeMu.Lock()
	defer v.closeMu.Unlock()
	select {
	case <-v.closed:
		return nil
	default:
		close(v.closed)
		return nil
	}
}

func (v *virtualPacketConn) SetDeadline(t time.Time) error {
	v.deadline.Store(&t)
	return nil
}

func (v *virtualPacketConn) SetReadDeadline(t time.Time) error {
	v.deadline.Store(&t)
	return nil
}

func (v *virtualPacketConn) SetWriteDeadline(time.Time) error { return nil }

// SetReadBuffer satisfies the optional interface quic-go probes for
// when sizing receive buffers. The real socket buffer lives on the
// parent connection; if the parent supports it, we forward the call,
// otherwise we silently accept the request.
func (v *virtualPacketConn) SetReadBuffer(bytes int) error {
	if rb, ok := v.parent.(interface{ SetReadBuffer(int) error }); ok {
		return rb.SetReadBuffer(bytes)
	}
	return nil
}

// SetWriteBuffer mirrors SetReadBuffer for the send side.
func (v *virtualPacketConn) SetWriteBuffer(bytes int) error {
	if wb, ok := v.parent.(interface{ SetWriteBuffer(int) error }); ok {
		return wb.SetWriteBuffer(bytes)
	}
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "mirage: virtual packet conn read deadline exceeded" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }
