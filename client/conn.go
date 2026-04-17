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
	"github.com/valtrogen/mirage/behavior"
	"github.com/valtrogen/mirage/congestion"
	"github.com/valtrogen/mirage/congestion/bbr2"
	"github.com/valtrogen/mirage/handshake"
	"github.com/valtrogen/mirage/padder"
	"github.com/valtrogen/mirage/proto"
	"github.com/valtrogen/mirage/recycle"
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

	// cids tracks every destination connection ID the peer has
	// authorised the client to send with, plus the sequence number
	// of the one currently in use. The handshake bootstraps it from
	// the server's adopted SCID; subsequent NEW_CONNECTION_ID frames
	// feed it so the senderLoop can rotate DCIDs on a Chrome-like
	// cadence (see Behavior.CIDRotateInterval).
	cids          *cidPool
	lastCIDRotate time.Time

	utlsConn *utls.UQUICConn

	mu                sync.Mutex
	pp                [4]struct{ read, write *transport.PacketProtection }
	cipherSuite       uint16
	pn                [4]uint64
	cryptoBuf         [4][]byte
	cryptoSent        [4]uint64
	cryptoRecvd       [4]uint64
	cryptoRecvBuf     [4]map[uint64][]byte
	ackPending        [4]bool
	recvWindow        [4]*replay.SlidingWindow
	serverDCIDAdopted bool
	// 1-RTT key-update state (RFC 9001 §6). Mirage tracks the
	// current and next-phase AEAD keys for both directions so it
	// can transparently follow a peer-initiated rotation. The
	// header protection key never changes across updates, so
	// nextRead/nextWrite share the headerMask of the current key.
	appReadSecret  []byte
	appWriteSecret []byte
	appNextRead    *transport.PacketProtection
	appNextWrite   *transport.PacketProtection
	recvKeyPhase   bool
	sendKeyPhase   bool

	streams *streamMap

	sentMu        sync.Mutex
	sent          map[uint64]*sentPacket
	bytesInFlight congestion.ByteCount
	// pmtuProbes records the size of PMTU probe packets so we can
	// call pmtuSearch.Confirmed when they are acknowledged.
	pmtuProbes map[uint64]uint16
	// sentTimes records the wall-clock send time of every 1-RTT
	// packet — both retransmittable ones (also held in c.sent) and
	// ACK-only ones — so processAppAck can compute an RFC 9002
	// §5.1 RTT sample for whichever packet number ends up being
	// the largest acknowledged. Entries are dropped on ack or loss.
	sentTimes map[uint64]time.Time
	// lostQueue holds packets the receiver loop has declared lost via
	// RFC 9002 §6.1 detection. The sender loop drains this queue on
	// every iteration of retransmitApp and immediately resends the
	// stream payload at a fresh packet number.
	lostQueue []*sentPacket
	// largestAckedPN is the highest 1-RTT packet number we have
	// observed in any incoming ACK. Loss detection compares against
	// this rather than the per-ack largest so out-of-order ACK frames
	// cannot regress the loss horizon.
	largestAckedPN     uint64
	largestAckedSentAt time.Time
	hasLargestAcked    bool

	rtt *congestion.RTTStats
	// cc is the congestion controller. Implementations are
	// responsible for their own internal locking; mirage drives
	// callbacks from both the sender and receiver goroutines.
	cc congestion.Controller

	// flowMu guards the connection-level flow control counters.
	// It is its own mutex (not c.mu) because the sender holds it
	// across nextSendChunk calls and we want to keep header / key
	// state on c.mu independent of the stream-data accounting.
	flowMu sync.Mutex
	// flowConnMaxData is the absolute byte offset across all
	// streams the peer has authorised us to send (RFC 9000 §19.9).
	// Initialised from the server's initial_max_data and ratcheted
	// upwards by MAX_DATA frames.
	flowConnMaxData uint64
	// flowConnSent is the running total of payload bytes we have
	// emitted across all streams. New chunks may only be sent when
	// flowConnSent + chunk <= flowConnMaxData.
	flowConnSent uint64
	// pendingMaxStreamData holds per-stream MAX_STREAM_DATA updates
	// that Stream.Read has queued. The senderLoop drains this map
	// and emits the corresponding frames.
	pendingMaxStreamData map[uint64]uint64
	// pendingResetStream and pendingStopSending hold abrupt
	// stream-termination frames Stream.Reset and Stream.CancelRead
	// have queued. Each map is keyed by stream ID.
	pendingResetStream map[uint64]pendingResetStream
	pendingStopSending map[uint64]uint64

	wakeCh chan struct{}

	pingClock  *behavior.PingClock
	padder     *padder.Padder
	pmtuSearch *behavior.PMTUSearch

	handshakeDone atomic.Bool
	closed        atomic.Bool
	readErr       atomic.Pointer[errBox]
	aeadDrops     atomic.Uint64

	serverTPRaw []byte
	serverTP    *transport.TransportParameters

	stopCh chan struct{}
	wg     sync.WaitGroup

	// controlStreamCh receives the first server-initiated bidi
	// stream when Config.OnRecycleHint is set. The control reader
	// goroutine drains it once and then loops on ReadControlFrame.
	controlStreamCh chan *Stream
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
	size    congestion.ByteCount
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

	bh := cfg.effectiveBehavior()
	rtt := congestion.NewRTTStats()
	rtt.SetMaxAckDelay(bh.MaxAckDelay)
	cc := bbr2.New(congestion.ByteCount(bh.MaxUDPPayloadSize), 0)
	c := &Conn{
		cfg:        cfg,
		pconn:      pconn,
		remote:     udpAddr,
		stopCh:     make(chan struct{}),
		wakeCh:     make(chan struct{}, 1),
		sent:       make(map[uint64]*sentPacket),
		sentTimes:  make(map[uint64]time.Time),
		pmtuProbes: make(map[uint64]uint16),
		rtt:        rtt,
		cc:         cc,
		pingClock:  behavior.NewPingClock(bh.PingInterval),
		padder:     padder.New(cfg.effectivePadderPolicy()),
		pmtuSearch: behavior.NewPMTUSearch(bh),
	}
	c.streams = newStreamMap(c)
	if cfg.OnRecycleHint != nil {
		c.controlStreamCh = make(chan *Stream, 1)
		c.streams.controlSink = c.controlStreamCh
	}
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
	// Pre-allocate the CID pool; it is populated for real once the
	// server's SCID is adopted. The retention limit mirrors the
	// active_connection_id_limit we advertise in transport
	// parameters so we never accept more than the peer is willing
	// to issue.
	cidLimit := behavior.Default().ActiveConnectionIDLimit
	if c.cfg != nil {
		cidLimit = c.cfg.effectiveBehavior().ActiveConnectionIDLimit
	}
	c.cids = newCIDPool(int(cidLimit))
	c.lastCIDRotate = time.Now()
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

	bh := c.cfg.effectiveBehavior()
	tp := &transport.TransportParameters{
		InitialSourceConnectionID: append([]byte(nil), c.scid...),
	}
	behavior.ApplyToTransportParameters(tp, bh)
	if to := c.cfg.effectiveIdleTimeout(); to > 0 {
		tp.MaxIdleTimeoutMillis = uint64(to / time.Millisecond)
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

	for i := range c.recvWindow {
		c.recvWindow[i] = replay.NewSlidingWindow(64)
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

	if c.controlStreamCh != nil {
		c.wg.Add(1)
		go c.controlStreamReader()
	}
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
			c.flowMu.Lock()
			if tp.InitialMaxData > c.flowConnMaxData {
				c.flowConnMaxData = tp.InitialMaxData
			}
			c.flowMu.Unlock()
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
	if lvl == levelApp {
		secretCopy := append([]byte(nil), secret...)
		nextSecret, err := transport.NextAppSecret(suite, secretCopy)
		if err != nil {
			return err
		}
		nextPP, err := transport.RekeyForUpdate(suite, pp, nextSecret)
		if err != nil {
			return err
		}
		if isRead {
			c.appReadSecret = secretCopy
			c.appNextRead = nextPP
		} else {
			c.appWriteSecret = secretCopy
			c.appNextWrite = nextPP
		}
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
	phase := c.sendKeyPhase
	c.mu.Unlock()
	if pp == nil {
		return
	}
	payload := transport.AppendConnectionCloseFrame(nil, code, 0, reason)
	pkt, err := transport.BuildShortHeader(c.sendDCID(), uint32(pn), payload, phase, pp)
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

// AEADDrops returns the number of 1-RTT datagrams the connection
// silently discarded after an AEAD or short-header parse failure.
// Counter only — observed values are useful for spotting key
// confusion, peer bugs, or path corruption without making the
// connection itself fail.
func (c *Conn) AEADDrops() uint64 { return c.aeadDrops.Load() }

// RTT returns the connection's RTT estimator. Callers may read its
// fields concurrently with the data plane; the returned pointer is
// stable for the lifetime of the connection.
func (c *Conn) RTT() *congestion.RTTStats { return c.rtt }

// BytesInFlight returns the number of payload bytes whose carrying
// 1-RTT packets have been written to the wire but not yet
// acknowledged or declared lost. Useful for tests and metrics.
func (c *Conn) BytesInFlight() uint64 {
	return uint64(c.snapshotBytesInFlight())
}

// CongestionController returns the controller installed on this
// connection. The returned value is stable for the connection's
// lifetime; callers may read controller state but must not swap it.
func (c *Conn) CongestionController() congestion.Controller { return c.cc }

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

// localInitialMaxStreamData returns the initial receive window we
// advertised for a stream with the given ID. This is the limit we
// told the peer in our transport parameters (RFC 9000 §18.2). It must
// stay in lock-step with behavior.ApplyToTransportParameters; the two
// read from the same Behavior config so they cannot drift.
func (c *Conn) localInitialMaxStreamData(streamID uint64) uint64 {
	cfg := c.cfg
	if cfg == nil {
		// Tests sometimes wire a Conn directly without a Config; fall
		// back to the canonical Chrome H3 profile so the initial
		// windows still match what we would advertise on the wire.
		def := behavior.Default()
		if streamID&0x01 != 0 {
			return def.InitialMaxStreamDataBidiRemote
		}
		return def.InitialMaxStreamDataBidiLocal
	}
	bh := cfg.effectiveBehavior()
	if streamID&0x01 != 0 {
		return bh.InitialMaxStreamDataBidiRemote
	}
	return bh.InitialMaxStreamDataBidiLocal
}

// controlStreamReader is the goroutine spawned when Config.OnRecycleHint
// is set. It waits for the dispatcher to surface the first
// server-initiated bidi stream, then loops reading control frames and
// fans them out to the registered callback.
//
// The reader exits when the stream returns an error (EOF, connection
// close) or when the connection is shutting down. Errors are logged
// via the connection's stored read-error so the operator can see them
// surface from later Read/Write calls.
func (c *Conn) controlStreamReader() {
	defer c.wg.Done()
	var cs *Stream
	select {
	case cs = <-c.controlStreamCh:
	case <-c.stopCh:
		return
	}
	for {
		t, body, err := ReadControlFrame(cs)
		if err != nil {
			return
		}
		if t == proto.FrameTypeConnectionRecycleHint {
			hint, err := recycle.DecodeHint(body)
			if err != nil {
				continue
			}
			if cb := c.cfg.OnRecycleHint; cb != nil {
				go cb(hint)
			}
		}
		// Unknown frame types are silently ignored, matching the
		// receiver-discipline rule documented in proto/frames.go.
	}
}

// queueMaxStreamData records that we need to send a MAX_STREAM_DATA
// frame for the given stream. The senderLoop picks these up and emits
// them on the next iteration.
func (c *Conn) queueMaxStreamData(streamID, maxData uint64) {
	c.flowMu.Lock()
	if c.pendingMaxStreamData == nil {
		c.pendingMaxStreamData = make(map[uint64]uint64)
	}
	c.pendingMaxStreamData[streamID] = maxData
	c.flowMu.Unlock()
	c.wakeSender()
}

// pendingResetStream is the per-stream record queued by
// Stream.Reset, awaiting emission by the sender loop.
type pendingResetStream struct {
	ErrorCode uint64
	FinalSize uint64
}

// queueResetStream records that we need to send a RESET_STREAM frame
// for streamID (RFC 9000 §19.4). The senderLoop drains the queue.
// Repeated calls overwrite; a stream is reset at most once.
func (c *Conn) queueResetStream(streamID, errorCode, finalSize uint64) {
	c.flowMu.Lock()
	if c.pendingResetStream == nil {
		c.pendingResetStream = make(map[uint64]pendingResetStream)
	}
	c.pendingResetStream[streamID] = pendingResetStream{
		ErrorCode: errorCode,
		FinalSize: finalSize,
	}
	c.flowMu.Unlock()
	c.wakeSender()
}

// queueStopSending records that we need to send a STOP_SENDING frame
// for streamID (RFC 9000 §19.5).
func (c *Conn) queueStopSending(streamID, errorCode uint64) {
	c.flowMu.Lock()
	if c.pendingStopSending == nil {
		c.pendingStopSending = make(map[uint64]uint64)
	}
	c.pendingStopSending[streamID] = errorCode
	c.flowMu.Unlock()
	c.wakeSender()
}

// wakeSender nudges the sender goroutine. Safe to call from any
// goroutine; non-blocking.
func (c *Conn) wakeSender() {
	select {
	case c.wakeCh <- struct{}{}:
	default:
	}
}
