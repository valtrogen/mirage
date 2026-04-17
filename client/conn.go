package client

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/valtrogen/mirage/handshake"
	"github.com/valtrogen/mirage/proto"
	"github.com/valtrogen/mirage/replay"
	"github.com/valtrogen/mirage/transport"
)

// encryptionLevel mirrors utls.QUICEncryptionLevel using the local
// transport package conventions.
type encryptionLevel int

const (
	levelInitial encryptionLevel = iota
	levelEarly
	levelHandshake
	levelApp
)

func levelFromUTLS(l utls.QUICEncryptionLevel) encryptionLevel {
	switch l {
	case utls.QUICEncryptionLevelInitial:
		return levelInitial
	case utls.QUICEncryptionLevelEarly:
		return levelEarly
	case utls.QUICEncryptionLevelHandshake:
		return levelHandshake
	case utls.QUICEncryptionLevelApplication:
		return levelApp
	}
	return levelInitial
}

// Conn is a connected mirage client. It owns the underlying UDP socket
// and the QUIC + TLS state machine.
type Conn struct {
	cfg    *Config
	pconn  net.PacketConn
	remote net.Addr

	dcid []byte
	scid []byte

	utlsConn *utls.UQUICConn

	mu                sync.Mutex
	pp                [4]struct{ read, write *transport.PacketProtection }
	cipherSuite       uint16
	pn                [4]uint64
	cryptoBuf         [4][]byte
	cryptoSent        [4]uint64
	cryptoRecvd       [4]uint64
	cryptoRecvBuf     [4]map[uint64][]byte
	largestRecvPN     [4]int64
	ackPending        [4]bool
	recvPNs           [4]map[uint64]struct{}
	serverDCIDAdopted bool

	streams *streamMap

	sentMu  sync.Mutex
	sent    map[uint64]*sentPacket
	rttSRTT time.Duration

	wakeCh chan struct{}

	handshakeDone atomic.Bool
	closed        atomic.Bool
	readErr       atomic.Pointer[errBox]

	serverTPRaw []byte
	serverTP    *transport.TransportParameters

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// errBox wraps an error so atomic.Pointer[errBox] can hold any
// concrete error type (sync/atomic.Value rejects mixed types).
type errBox struct{ err error }

// storeReadErr records the first failure on the connection. Subsequent
// failures are dropped.
func (c *Conn) storeReadErr(err error) {
	if err == nil {
		return
	}
	c.readErr.CompareAndSwap(nil, &errBox{err: err})
}

// loadReadErr returns the stored failure or nil.
func (c *Conn) loadReadErr() error {
	if b := c.readErr.Load(); b != nil {
		return b.err
	}
	return nil
}

// sentPacket records a 1-RTT packet we sent so that we can retransmit
// the STREAM frames it carried if the peer never ACKs it.
type sentPacket struct {
	pn      uint64
	sentAt  time.Time
	streams []sentStreamFrame
	retries int
}

type sentStreamFrame struct {
	streamID uint64
	offset   uint64
	data     []byte
	fin      bool
}

// Dial opens a mirage connection to addr ("host:port").
func Dial(ctx context.Context, addr string, cfg *Config) (*Conn, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("mirage/client: resolve %s: %w", addr, err)
	}
	pconn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return nil, fmt.Errorf("mirage/client: listen: %w", err)
	}

	c := &Conn{
		cfg:     cfg,
		pconn:   pconn,
		remote:  udpAddr,
		stopCh:  make(chan struct{}),
		wakeCh:  make(chan struct{}, 1),
		sent:    make(map[uint64]*sentPacket),
		rttSRTT: 100 * time.Millisecond,
	}
	c.streams = newStreamMap(c)
	if err := c.init(ctx); err != nil {
		_ = pconn.Close()
		return nil, err
	}
	return c, nil
}

func (c *Conn) init(ctx context.Context) error {
	c.dcid = make([]byte, 8)
	c.scid = make([]byte, 8)
	if _, err := rand.Read(c.dcid); err != nil {
		return err
	}
	if _, err := rand.Read(c.scid); err != nil {
		return err
	}
	icp, err := transport.DeriveClientInitialProtection(c.dcid)
	if err != nil {
		return err
	}
	isp, err := transport.DeriveServerInitialProtection(c.dcid)
	if err != nil {
		return err
	}
	c.pp[levelInitial].write = icp
	c.pp[levelInitial].read = isp

	windowID := replay.CurrentWindowID()
	windowKey, err := replay.DeriveWindowKey(c.cfg.MasterKey[:], windowID)
	if err != nil {
		return fmt.Errorf("mirage/client: derive window key: %w", err)
	}
	var sid [proto.SessionIDLen]byte
	if err := handshake.EncodeSessionID(sid[:], windowKey, c.cfg.ShortID[:], windowID); err != nil {
		return fmt.Errorf("mirage/client: encode session id: %w", err)
	}

	tlsConf := c.cfg.TLSConfig
	if tlsConf == nil {
		tlsConf = &tls.Config{}
	} else {
		tlsConf = tlsConf.Clone()
	}
	tlsConf.MinVersion = tls.VersionTLS13
	tlsConf.MaxVersion = tls.VersionTLS13
	tlsConf.ServerName = c.cfg.ServerName
	tlsConf.NextProtos = c.cfg.effectiveALPN()
	utlsConfTLS := translateTLSConfig(tlsConf)

	uqc := utls.UQUICClient(&utls.QUICConfig{TLSConfig: utlsConfTLS}, c.cfg.effectiveHelloID())

	spec, err := utls.UTLSIdToSpec(c.cfg.effectiveHelloID())
	if err != nil {
		return fmt.Errorf("mirage/client: load Chrome spec: %w", err)
	}
	spec.GetSessionID = func(ticket []byte) [32]byte { return sid }
	overrideALPN(&spec, c.cfg.effectiveALPN())
	restrictToTLS13(&spec)

	tp := &transport.TransportParameters{
		MaxIdleTimeoutMillis:           uint64(c.cfg.effectiveIdleTimeout() / time.Millisecond),
		MaxUDPPayloadSize:              1452,
		InitialMaxData:                 1 << 22,
		InitialMaxStreamDataBidiLocal:  1 << 20,
		InitialMaxStreamDataBidiRemote: 1 << 20,
		InitialMaxStreamDataUni:        1 << 20,
		InitialMaxStreamsBidi:          0,
		InitialMaxStreamsUni:           3,
		AckDelayExponent:               3,
		MaxAckDelayMillis:              25,
		ActiveConnectionIDLimit:        4,
		DisableActiveMigration:         true,
		InitialSourceConnectionID:      append([]byte(nil), c.scid...),
	}
	tpBytes := tp.Marshal()
	addQUICTransportParameters(&spec, tpBytes)

	if err := uqc.ApplyPreset(&spec); err != nil {
		return fmt.Errorf("mirage/client: apply preset: %w", err)
	}
	utlsConfTLS.MinVersion = utls.VersionTLS13
	utlsConfTLS.MaxVersion = utls.VersionTLS13

	if err := injectSessionID(uqc, sid[:]); err != nil {
		return fmt.Errorf("mirage/client: inject session id: %w", err)
	}

	uqc.SetTransportParameters(tpBytes)
	c.utlsConn = uqc

	hctx, cancel := context.WithTimeout(ctx, c.cfg.effectiveHandshakeTimeout())
	defer cancel()
	if err := uqc.Start(hctx); err != nil {
		return fmt.Errorf("mirage/client: tls Start: %w", err)
	}

	for i := range c.largestRecvPN {
		c.largestRecvPN[i] = -1
	}

	c.wg.Add(1)
	go c.readLoop()

	deadline := time.Now().Add(c.cfg.effectiveHandshakeTimeout())
	if d, ok := hctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	if err := c.driveHandshakeLoop(deadline); err != nil {
		_ = c.Close()
		return err
	}

	c.wg.Add(1)
	go c.senderLoop()
	return nil
}

// pumpEvents drains uTLS events until QUICNoEvent and ships any
// outbound CRYPTO data and key installs.
func (c *Conn) pumpEvents() error {
	for {
		ev := c.utlsConn.NextEvent()
		switch ev.Kind {
		case utls.QUICNoEvent:
			return nil
		case utls.QUICSetReadSecret:
			dbg("uTLS event: SetReadSecret level=%d suite=0x%x", ev.Level, ev.Suite)
			if err := c.installSecret(levelFromUTLS(ev.Level), ev.Suite, ev.Data, true); err != nil {
				return err
			}
		case utls.QUICSetWriteSecret:
			dbg("uTLS event: SetWriteSecret level=%d suite=0x%x", ev.Level, ev.Suite)
			if err := c.installSecret(levelFromUTLS(ev.Level), ev.Suite, ev.Data, false); err != nil {
				return err
			}
		case utls.QUICWriteData:
			dbg("uTLS event: WriteData level=%d size=%d", ev.Level, len(ev.Data))
			c.appendCrypto(levelFromUTLS(ev.Level), ev.Data)
		case utls.QUICTransportParameters:
			dbg("uTLS event: TransportParameters size=%d", len(ev.Data))
			c.serverTPRaw = append([]byte(nil), ev.Data...)
			tp, err := transport.ParseTransportParameters(c.serverTPRaw)
			if err != nil {
				return fmt.Errorf("mirage/client: parse server transport params: %w", err)
			}
			c.serverTP = tp
		case utls.QUICHandshakeDone:
			dbg("uTLS event: HandshakeDone")
			c.handshakeDone.Store(true)
		default:
			dbg("uTLS event: kind=%d level=%d size=%d", ev.Kind, ev.Level, len(ev.Data))
		}
	}
}

func (c *Conn) installSecret(lvl encryptionLevel, suite uint16, secret []byte, isRead bool) error {
	pp, err := transport.DerivePacketProtection(suite, secret)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cipherSuite == 0 {
		c.cipherSuite = suite
	}
	if isRead {
		c.pp[lvl].read = pp
	} else {
		c.pp[lvl].write = pp
	}
	return nil
}

func (c *Conn) appendCrypto(lvl encryptionLevel, data []byte) {
	c.mu.Lock()
	c.cryptoBuf[lvl] = append(c.cryptoBuf[lvl], data...)
	c.mu.Unlock()
}

// Close shuts down the UDP socket and stops the read loop. If the
// 1-RTT keys are installed it also emits a single CONNECTION_CLOSE so
// the peer can release its connection state immediately instead of
// waiting for the idle timeout.
func (c *Conn) Close() error {
	if !c.closed.CompareAndSwap(false, true) {
		return nil
	}
	c.sendConnectionClose(0, "")
	close(c.stopCh)
	c.wakeSender()
	if c.streams != nil {
		c.streams.shutdown(ErrStreamClosed)
	}
	if c.utlsConn != nil {
		_ = c.utlsConn.Close()
	}
	err := c.pconn.Close()
	c.wg.Wait()
	return err
}

// sendConnectionClose builds and writes one application-level
// CONNECTION_CLOSE packet using the current 1-RTT keys. Errors are
// swallowed: this is best-effort cleanup.
func (c *Conn) sendConnectionClose(code uint64, reason string) {
	c.mu.Lock()
	pp := c.pp[levelApp].write
	pn := c.pn[levelApp]
	c.pn[levelApp] = pn + 1
	c.mu.Unlock()
	if pp == nil {
		return
	}
	payload := transport.AppendConnectionCloseFrame(nil, code, 0, reason)
	pkt, err := transport.BuildShortHeader(c.dcid, uint32(pn), payload, false, pp)
	if err != nil {
		return
	}
	_, _ = c.pconn.WriteTo(pkt, c.remote)
}

func (c *Conn) readLoop() {
	defer c.wg.Done()
	defer c.failStreams()
	buf := make([]byte, 1500)
	for {
		select {
		case <-c.stopCh:
			return
		default:
		}
		_ = c.pconn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, _, err := c.pconn.ReadFrom(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			c.storeReadErr(err)
			return
		}
		if err := c.processDatagram(append([]byte(nil), buf[:n]...)); err != nil {
			c.storeReadErr(err)
			return
		}
	}
}

// failStreams aborts all in-flight reads/writes on every stream once
// the read loop exits. Without this, a stream Read could block forever
// waiting on data after the underlying socket has died.
func (c *Conn) failStreams() {
	if c.streams == nil {
		return
	}
	err := ErrStreamClosed
	if e := c.loadReadErr(); e != nil {
		err = e
	}
	c.streams.shutdown(err)
}

// LocalAddr returns the local UDP address bound for this connection.
func (c *Conn) LocalAddr() net.Addr { return c.pconn.LocalAddr() }

// RemoteAddr returns the server's UDP address.
func (c *Conn) RemoteAddr() net.Addr { return c.remote }

// HandshakeComplete reports whether the TLS handshake has finished.
func (c *Conn) HandshakeComplete() bool { return c.handshakeDone.Load() }

// OpenStream allocates a new client-initiated bidirectional stream. It
// does not block on the network; failures surface from Read/Write.
func (c *Conn) OpenStream(ctx context.Context) (*Stream, error) {
	if c.closed.Load() {
		return nil, ErrStreamClosed
	}
	if !c.handshakeDone.Load() {
		return nil, errors.New("mirage/client: OpenStream before handshake complete")
	}
	return c.streams.openLocal(), nil
}

// AcceptStream blocks until the peer opens a new bidirectional stream
// or the connection terminates.
func (c *Conn) AcceptStream(ctx context.Context) (*Stream, error) {
	if c.closed.Load() {
		return nil, ErrStreamClosed
	}
	type result struct {
		s   *Stream
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		s, err := c.streams.accept()
		resCh <- result{s, err}
	}()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case r := <-resCh:
		return r.s, r.err
	}
}

// wakeSender nudges the sender goroutine. Safe to call from any
// goroutine; non-blocking.
func (c *Conn) wakeSender() {
	select {
	case c.wakeCh <- struct{}{}:
	default:
	}
}
