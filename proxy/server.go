package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/handshake"
	"github.com/valtrogen/mirage/metrics"
	"github.com/valtrogen/mirage/recycle"
)

// DefaultRequestReadTimeout bounds how long the server waits for the
// client to send the request frame after opening a stream. A peer that
// stalls past this deadline is dropped without dialing upstream.
const DefaultRequestReadTimeout = 15 * time.Second

// DefaultDialTimeout bounds the upstream TCP dial.
const DefaultDialTimeout = 30 * time.Second

// DefaultStreamIdleTimeout is the per-stream inactivity ceiling applied
// during the bridge phase. It is enforced independently of QUIC's
// transport idle timeout so that a stuck TCP backend cannot hold a
// mirage stream open indefinitely. Zero disables the timer.
const DefaultStreamIdleTimeout = 5 * time.Minute

// Server bridges authenticated mirage streams to outbound TCP
// connections. One Server is safe for concurrent use across many
// handshake.Conn values.
//
// All fields are optional; sensible defaults are wired by Serve.
type Server struct {
	// Authorizer decides whether a stream's requested target is
	// permitted. nil means adapter.AllowAllProxyAuthorizer, which is
	// only appropriate for development.
	Authorizer adapter.ProxyAuthorizer

	// Dialer is the net.Dialer used for upstream connections. nil
	// means a dialer with DefaultDialTimeout.
	Dialer *net.Dialer

	// RequestReadTimeout overrides DefaultRequestReadTimeout.
	RequestReadTimeout time.Duration

	// StreamIdleTimeout overrides DefaultStreamIdleTimeout. A negative
	// value disables the per-stream idle timer.
	StreamIdleTimeout time.Duration

	// Logger receives operational events. nil means slog.DiscardHandler.
	Logger *slog.Logger

	// Metrics receives counters and gauges. nil means metrics.Discard.
	Metrics metrics.Sink

	initOnce      sync.Once
	mAccepted     metrics.Counter
	mDialed       metrics.Counter
	mDialFailed   metrics.Counter
	mUnauthorized metrics.Counter
	mBadRequest   metrics.Counter
	mIdleClosed   metrics.Counter
	mLive         metrics.Gauge
	mBytesUp      metrics.Counter
	mBytesDown    metrics.Counter

	mUDPLive       metrics.Gauge
	mUDPPktsUp     metrics.Counter
	mUDPPktsDown   metrics.Counter
	mUDPBytesUp    metrics.Counter
	mUDPBytesDown  metrics.Counter
	mUDPDropResolv metrics.Counter
	mUDPDropAuth   metrics.Counter
}

func (s *Server) init() {
	s.initOnce.Do(func() {
		if s.Authorizer == nil {
			s.Authorizer = adapter.AllowAllProxyAuthorizer{}
		}
		if s.Dialer == nil {
			s.Dialer = &net.Dialer{Timeout: DefaultDialTimeout}
		}
		if s.RequestReadTimeout == 0 {
			s.RequestReadTimeout = DefaultRequestReadTimeout
		}
		if s.StreamIdleTimeout == 0 {
			s.StreamIdleTimeout = DefaultStreamIdleTimeout
		}
		if s.Logger == nil {
			s.Logger = slog.New(slog.DiscardHandler)
		}
		if s.Metrics == nil {
			s.Metrics = metrics.Discard
		}
		s.mAccepted = s.Metrics.Counter("proxy.streams_accepted")
		s.mDialed = s.Metrics.Counter("proxy.dial_ok")
		s.mDialFailed = s.Metrics.Counter("proxy.dial_fail")
		s.mUnauthorized = s.Metrics.Counter("proxy.unauthorized")
		s.mBadRequest = s.Metrics.Counter("proxy.bad_request")
		s.mIdleClosed = s.Metrics.Counter("proxy.idle_closed")
		s.mLive = s.Metrics.Gauge("proxy.live_streams")
		s.mBytesUp = s.Metrics.Counter("proxy.bytes_upstream")
		s.mBytesDown = s.Metrics.Counter("proxy.bytes_downstream")
		s.mUDPLive = s.Metrics.Gauge("proxy.udp.live_streams")
		s.mUDPPktsUp = s.Metrics.Counter("proxy.udp.packets_upstream")
		s.mUDPPktsDown = s.Metrics.Counter("proxy.udp.packets_downstream")
		s.mUDPBytesUp = s.Metrics.Counter("proxy.udp.bytes_upstream")
		s.mUDPBytesDown = s.Metrics.Counter("proxy.udp.bytes_downstream")
		s.mUDPDropResolv = s.Metrics.Counter("proxy.udp.drop_resolve")
		s.mUDPDropAuth = s.Metrics.Counter("proxy.udp.drop_auth")
	})
}

// Serve accepts streams from conn in a loop and bridges each one to an
// outbound TCP connection. It returns when conn.AcceptStream returns
// an error or ctx is cancelled. Streams that are still bridging when
// Serve returns continue to run until their own copy loops finish; the
// caller can synchronise on conn's context if a hard barrier is
// required.
//
// If the connection has a recycle Tracker (configured via
// handshake.Server.RecycleBounds), Serve opens a control stream and
// sends a CONNECTION_RECYCLE_HINT when the threshold is reached.
func (s *Server) Serve(ctx context.Context, conn *handshake.Conn) error {
	if conn == nil {
		return errors.New("mirage/proxy: nil handshake.Conn")
	}
	s.init()

	// Set up recycle tracking if configured.
	var tracker *recycle.Tracker
	var hintSent atomic.Bool
	var controlStream *quic.Stream
	if conn.Tracker != nil {
		tracker = conn.Tracker
		// Open a bidirectional control stream for the HINT. Per
		// proto/frames.go, control frames travel on a single bidi
		// stream opened by the server right after handshake. The
		// client receives this via AcceptStream and can read hints.
		cs, err := conn.OpenStream()
		if err != nil {
			s.Logger.Warn("proxy: failed to open control stream",
				slog.String("err", err.Error()))
		} else {
			controlStream = cs
		}
	}

	for {
		st, err := conn.AcceptStream(ctx)
		if err != nil {
			if controlStream != nil {
				_ = controlStream.Close()
			}
			return err
		}
		s.mAccepted.Add(1)
		go s.handleStreamWithRecycle(ctx, conn.UserID, st, tracker, &hintSent, controlStream)
	}
}

func (s *Server) handleStream(ctx context.Context, uid adapter.UserID, st *quic.Stream) {
	s.handleStreamCore(ctx, uid, st, nil, nil, nil)
}

func (s *Server) handleStreamWithRecycle(
	ctx context.Context,
	uid adapter.UserID,
	st *quic.Stream,
	tracker *recycle.Tracker,
	hintSent *atomic.Bool,
	controlStream *quic.Stream,
) {
	s.handleStreamCore(ctx, uid, st, tracker, hintSent, controlStream)
}

func (s *Server) handleStreamCore(
	ctx context.Context,
	uid adapter.UserID,
	st *quic.Stream,
	tracker *recycle.Tracker,
	hintSent *atomic.Bool,
	controlStream *quic.Stream,
) {
	s.mLive.Add(1)
	defer s.mLive.Add(-1)
	defer st.Close()

	if dl := time.Now().Add(s.RequestReadTimeout); !dl.IsZero() {
		_ = st.SetReadDeadline(dl)
	}
	req, err := ReadRequest(st)
	_ = st.SetReadDeadline(time.Time{})
	if err != nil {
		s.mBadRequest.Add(1)
		s.Logger.Debug("proxy: read request failed",
			slog.String("err", err.Error()))
		s.writeResponse(st, Response{Status: StatusBadRequest, Reason: "bad request"})
		return
	}

	switch req.Cmd {
	case CmdTCPConnect:
		// fall through to TCP handler below
	case CmdUDPAssociate:
		if err := s.writeResponse(st, Response{Status: StatusOK}); err != nil {
			s.Logger.Debug("proxy: write UDP OK response failed",
				slog.String("err", err.Error()))
			return
		}
		s.handleUDPAssociate(ctx, uid, st)
		return
	default:
		s.mBadRequest.Add(1)
		s.writeResponse(st, Response{Status: StatusBadRequest, Reason: "unsupported cmd"})
		return
	}

	if err := s.Authorizer.AuthorizeTCP(ctx, uid, req.Host, req.Port); err != nil {
		s.mUnauthorized.Add(1)
		s.Logger.Info("proxy: target denied",
			slog.String("host", req.Host),
			slog.Int("port", int(req.Port)),
			slog.String("err", err.Error()))
		s.writeResponse(st, Response{Status: StatusNotAllowed, Reason: err.Error()})
		return
	}

	target := net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port)))
	upstream, err := s.Dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		s.mDialFailed.Add(1)
		s.Logger.Info("proxy: upstream dial failed",
			slog.String("target", target),
			slog.String("err", err.Error()))
		s.writeResponse(st, Response{Status: classifyDialErr(err), Reason: err.Error()})
		return
	}
	defer upstream.Close()
	s.mDialed.Add(1)

	if err := s.writeResponse(st, Response{Status: StatusOK}); err != nil {
		s.Logger.Debug("proxy: write OK response failed",
			slog.String("err", err.Error()))
		return
	}

	s.bridgeWithRecycle(st, upstream, tracker, hintSent, controlStream)
}

func (s *Server) writeResponse(st *quic.Stream, r Response) error {
	_, err := r.WriteTo(st)
	return err
}

// bridge copies bytes between the mirage stream and the upstream TCP
// connection until both halves close. It enforces the standard
// half-close pattern so that one side seeing EOF propagates a FIN to
// the other.
func (s *Server) bridge(st *quic.Stream, upstream net.Conn) {
	s.bridgeCore(st, upstream, nil, nil, nil)
}

func (s *Server) bridgeWithRecycle(
	st *quic.Stream,
	upstream net.Conn,
	tracker *recycle.Tracker,
	hintSent *atomic.Bool,
	controlStream *quic.Stream,
) {
	s.bridgeCore(st, upstream, tracker, hintSent, controlStream)
}

func (s *Server) bridgeCore(
	st *quic.Stream,
	upstream net.Conn,
	tracker *recycle.Tracker,
	hintSent *atomic.Bool,
	controlStream *quic.Stream,
) {
	var lastActivity atomic.Int64
	lastActivity.Store(time.Now().UnixNano())

	stop := make(chan struct{})
	if s.StreamIdleTimeout > 0 {
		go s.idleWatchdog(st, upstream, &lastActivity, stop)
	}

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		n, _ := copyTracking(upstream, st, &lastActivity)
		s.mBytesUp.Add(uint64(n))
		if tracker != nil {
			tracker.AddBytes(uint64(n))
			s.maybeRecycleHint(tracker, hintSent, controlStream)
		}
		if cw, ok := upstream.(closeWriter); ok {
			_ = cw.CloseWrite()
		} else {
			_ = upstream.Close()
		}
	}()

	go func() {
		defer wg.Done()
		n, _ := copyTracking(st, upstream, &lastActivity)
		s.mBytesDown.Add(uint64(n))
		if tracker != nil {
			tracker.AddBytes(uint64(n))
			s.maybeRecycleHint(tracker, hintSent, controlStream)
		}
		_ = st.Close()
	}()

	wg.Wait()
	close(stop)
}

// idleWatchdog closes both halves of the bridge when no byte has been
// observed in either direction for StreamIdleTimeout. It exits when
// stop is closed (i.e. the bridge finished naturally).
func (s *Server) idleWatchdog(
	st *quic.Stream,
	upstream net.Conn,
	last *atomic.Int64,
	stop <-chan struct{},
) {
	idle := s.StreamIdleTimeout
	tick := idle / 4
	if tick < 250*time.Millisecond {
		tick = 250 * time.Millisecond
	}
	t := time.NewTicker(tick)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case now := <-t.C:
			if now.UnixNano()-last.Load() < idle.Nanoseconds() {
				continue
			}
			s.mIdleClosed.Add(1)
			s.Logger.Debug("proxy: stream idle timeout, tearing down",
				slog.Duration("idle", idle))
			// Cancel both halves with explicit application error
			// codes so the client sees an unambiguous reason rather
			// than a silent FIN or RST. ProxyErrIdleTimeout is also
			// used by the client.Pool when surfacing the error.
			st.CancelRead(quic.StreamErrorCode(ProxyErrIdleTimeout))
			st.CancelWrite(quic.StreamErrorCode(ProxyErrIdleTimeout))
			_ = upstream.Close()
			return
		}
	}
}

// copyTracking is io.Copy that also bumps last on every successful
// short read so the idle watchdog can tell traffic is flowing.
func copyTracking(dst io.Writer, src io.Reader, last *atomic.Int64) (int64, error) {
	const bufSize = 32 * 1024
	buf := make([]byte, bufSize)
	var total int64
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			last.Store(time.Now().UnixNano())
			nw, ew := dst.Write(buf[:nr])
			total += int64(nw)
			if ew != nil {
				return total, ew
			}
			if nr != nw {
				return total, io.ErrShortWrite
			}
		}
		if er != nil {
			if er == io.EOF {
				return total, nil
			}
			return total, er
		}
	}
}

// maybeRecycleHint checks if the tracker threshold is reached and, if so,
// sends a CONNECTION_RECYCLE_HINT on the control stream exactly once.
func (s *Server) maybeRecycleHint(
	tracker *recycle.Tracker,
	hintSent *atomic.Bool,
	controlStream *quic.Stream,
) {
	if tracker == nil || hintSent == nil || controlStream == nil {
		return
	}
	if !tracker.Reached() {
		return
	}
	if !hintSent.CompareAndSwap(false, true) {
		return
	}
	hint := recycle.Hint{HandoffWindow: recycle.DefaultHandoffWindow}
	if err := recycle.WriteHint(controlStream, hint); err != nil {
		s.Logger.Warn("proxy: failed to write recycle hint",
			slog.String("err", err.Error()))
	} else {
		s.Logger.Info("proxy: sent CONNECTION_RECYCLE_HINT",
			slog.Duration("age", tracker.Age()),
			slog.Uint64("bytes", tracker.Bytes()))
	}
}

type closeWriter interface {
	CloseWrite() error
}

// classifyDialErr maps a net.Dialer error to the closest proxy status
// code. Anything we cannot categorise becomes StatusGeneralFail.
func classifyDialErr(err error) Status {
	var oe *net.OpError
	if errors.As(err, &oe) {
		var se syscall.Errno
		if errors.As(oe.Err, &se) {
			switch se {
			case syscall.ECONNREFUSED:
				return StatusConnRefused
			case syscall.EHOSTUNREACH:
				return StatusHostUnreach
			case syscall.ENETUNREACH:
				return StatusNetworkUnreach
			case syscall.ETIMEDOUT:
				return StatusTTLExpired
			}
		}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return StatusTTLExpired
	}
	return StatusGeneralFail
}
