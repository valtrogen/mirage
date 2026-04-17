package proxy

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/valtrogen/mirage/adapter"
)

// DefaultUDPAssociateIdleTimeout caps how long a UDP-associate stream
// can sit without traffic in either direction. Most UDP applications
// (DNS, QUIC keep-alive) churn well inside this window; anything that
// has been silent for the timeout is almost certainly an abandoned
// session that we want to reclaim socket FDs for.
const DefaultUDPAssociateIdleTimeout = 2 * time.Minute

// handleUDPAssociate runs the UDP relay state machine for one stream.
// It binds an ephemeral UDP socket, frame-decodes datagrams off the
// stream into outbound sendto(2) calls, and frame-encodes inbound
// datagrams from the socket back onto the stream.
//
// Lifecycle: returns when the stream's read side EOFs, the UDP socket
// errors out, or the per-association idle watchdog fires. The stream
// is left to the caller's defer to close.
func (s *Server) handleUDPAssociate(ctx context.Context, uid adapter.UserID, st *quic.Stream) {
	uconn, err := net.ListenUDP("udp", nil)
	if err != nil {
		s.Logger.Warn("proxy: udp associate ListenUDP failed",
			slog.String("err", err.Error()))
		return
	}
	defer uconn.Close()

	s.mUDPLive.Add(1)
	defer s.mUDPLive.Add(-1)

	idle := s.StreamIdleTimeout
	if idle == 0 {
		idle = DefaultUDPAssociateIdleTimeout
	}

	// resolveCache memoises the most recent destination per (host,
	// port) so rapid-fire DNS queries do not pay the resolver cost on
	// every datagram. The cache is bounded by simply replacing the
	// last entry — UDP applications normally hit one destination per
	// stream so a 1-slot cache is enough; larger caches would invite
	// memory growth on adversarial traffic.
	type destKey struct {
		host string
		port uint16
	}
	var (
		cacheMu  sync.Mutex
		cacheKey destKey
		cacheAddr *net.UDPAddr
	)
	resolve := func(host string, port uint16) (*net.UDPAddr, error) {
		cacheMu.Lock()
		defer cacheMu.Unlock()
		k := destKey{host: host, port: port}
		if cacheAddr != nil && k == cacheKey {
			return cacheAddr, nil
		}
		ua, err := net.ResolveUDPAddr("udp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			return nil, err
		}
		cacheKey = k
		cacheAddr = ua
		return ua, nil
	}

	stop := make(chan struct{})
	var stopOnce sync.Once
	closeAssoc := func() {
		stopOnce.Do(func() {
			close(stop)
			_ = uconn.Close()
			st.CancelRead(quic.StreamErrorCode(0))
			st.CancelWrite(quic.StreamErrorCode(0))
		})
	}

	// idle watchdog
	var lastActivityNs int64
	touch := func() {
		lastActivityNs = time.Now().UnixNano()
	}
	touch()
	go func() {
		t := time.NewTicker(idle / 4)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ctx.Done():
				closeAssoc()
				return
			case now := <-t.C:
				if now.UnixNano()-lastActivityNs >= idle.Nanoseconds() {
					s.mIdleClosed.Add(1)
					s.Logger.Debug("proxy: udp associate idle, tearing down",
						slog.Duration("idle", idle))
					closeAssoc()
					return
				}
			}
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)

	// Stream → upstream UDP.
	go func() {
		defer wg.Done()
		defer closeAssoc()
		for {
			frame, err := ReadUDPFrame(st)
			if err != nil {
				if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
					s.Logger.Debug("proxy: udp associate stream read",
						slog.String("err", err.Error()))
				}
				return
			}
			if err := s.Authorizer.AuthorizeUDP(ctx, uid, frame.Host, frame.Port); err != nil {
				s.mUDPDropAuth.Add(1)
				continue
			}
			ua, err := resolve(frame.Host, frame.Port)
			if err != nil {
				s.mUDPDropResolv.Add(1)
				s.Logger.Debug("proxy: udp resolve failed",
					slog.String("host", frame.Host),
					slog.String("err", err.Error()))
				continue
			}
			if _, err := uconn.WriteTo(frame.Payload, ua); err != nil {
				s.Logger.Debug("proxy: udp upstream write failed",
					slog.String("err", err.Error()))
				continue
			}
			s.mUDPPktsUp.Add(1)
			s.mUDPBytesUp.Add(uint64(len(frame.Payload)))
			touch()
		}
	}()

	// Upstream UDP → stream.
	go func() {
		defer wg.Done()
		defer closeAssoc()
		// 64 KiB is a safe ceiling for any UDP datagram observed on a
		// real link; smaller packets are returned with their actual
		// length.
		buf := make([]byte, 64*1024)
		for {
			n, src, err := uconn.ReadFrom(buf)
			if err != nil {
				if !errors.Is(err, net.ErrClosed) {
					s.Logger.Debug("proxy: udp upstream read",
						slog.String("err", err.Error()))
				}
				return
			}
			ua, ok := src.(*net.UDPAddr)
			if !ok {
				continue
			}
			frame := UDPFrame{
				Host:    ua.IP.String(),
				Port:    uint16(ua.Port),
				Payload: buf[:n],
			}
			out, err := AppendUDPFrame(nil, frame)
			if err != nil {
				continue
			}
			if _, err := st.Write(out); err != nil {
				return
			}
			s.mUDPPktsDown.Add(1)
			s.mUDPBytesDown.Add(uint64(n))
			touch()
		}
	}()

	wg.Wait()
}
