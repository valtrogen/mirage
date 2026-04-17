package handshake

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/valtrogen/mirage/adapter"
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

	// QUICConfig is the underlying QUIC configuration. If nil, quic-go
	// defaults are used.
	QUICConfig *quic.Config

	// MasterKey is the 32-byte mirage master key used to derive
	// time-window AEAD keys. Required.
	MasterKey []byte

	// Authenticator resolves a verified short-id to a user identity.
	// Required.
	Authenticator adapter.UserAuthenticator

	// SNITargets supplies the relay pool. If nil, unauthenticated
	// traffic is dropped instead of being forwarded.
	SNITargets adapter.SNITargetProvider

	// SessionTTL bounds dispatcher 4-tuple state. Zero uses the
	// dispatcher default (5 minutes).
	SessionTTL time.Duration

	dispatcher *Dispatcher
	vpc        *virtualPacketConn
	transport  *quic.Transport
	listener   *quic.Listener
	started    atomic.Bool
}

// Conn is an accepted mirage QUIC connection together with the user
// identity that authenticated it.
type Conn struct {
	*quic.Conn
	UserID adapter.UserID
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

	keyring, err := NewKeyring(s.MasterKey)
	if err != nil {
		return err
	}

	s.vpc = newVirtualPacketConn(s.PacketConn)
	s.dispatcher = &Dispatcher{
		PacketConn:    s.PacketConn,
		Keyring:       keyring,
		Authenticator: s.Authenticator,
		SNITargets:    s.SNITargets,
		SessionTTL:    s.SessionTTL,
		AuthSink:      s.vpc.in,
	}
	if err := s.dispatcher.Start(); err != nil {
		return err
	}

	s.transport = &quic.Transport{Conn: s.vpc}
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
func (s *Server) Accept(ctx context.Context) (*Conn, error) {
	if s.listener == nil {
		return nil, errors.New("mirage: Server not started")
	}
	c, err := s.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	uid, _ := s.dispatcher.UserIDFor(c.RemoteAddr())
	return &Conn{Conn: c, UserID: uid}, nil
}

// Close stops the listener, the dispatcher, and the virtual packet
// conn. It does not close PacketConn; the caller owns it.
//
// Order matters: the virtual packet conn must be closed first so that
// quic-go's Transport read loop unblocks, otherwise Transport.Close
// would deadlock waiting on a goroutine parked in vpc.ReadFrom.
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

func newVirtualPacketConn(parent net.PacketConn) *virtualPacketConn {
	return &virtualPacketConn{
		parent: parent,
		in:     make(chan AuthDatagram, 256),
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
