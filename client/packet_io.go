package client

import (
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/valtrogen/mirage/behavior"
	"github.com/valtrogen/mirage/congestion"
	"github.com/valtrogen/mirage/congestion/bbr2"
	"github.com/valtrogen/mirage/replay"
	"github.com/valtrogen/mirage/transport"
)

var debugLog = log.New(os.Stderr, "[mirage-client] ", log.LstdFlags|log.Lmicroseconds)
var debugEnabled = os.Getenv("MIRAGE_CLIENT_DEBUG") != ""

func dbg(f string, args ...any) {
	if debugEnabled {
		debugLog.Printf(f, args...)
	}
}

// flushLevel builds and sends one packet at lvl carrying any pending
// CRYPTO data and any pending ACK. It is a no-op when there is nothing
// to send.
func (c *Conn) flushLevel(lvl encryptionLevel) error {
	c.mu.Lock()
	pp := c.pp[lvl].write
	pendingCrypto := c.cryptoBuf[lvl]
	cryptoOff := c.cryptoSent[lvl]
	ackPending := c.ackPending[lvl]
	pn := c.pn[lvl]
	var ackLast, ackBitmap uint64
	var ackSeeded bool
	if ackPending && c.recvWindow[lvl] != nil {
		ackLast, ackBitmap, ackSeeded = c.recvWindow[lvl].Snapshot()
	}
	c.mu.Unlock()

	if pp == nil {
		return nil
	}
	if len(pendingCrypto) == 0 && !ackPending {
		return nil
	}

	var payload []byte
	if ackSeeded {
		payload = transport.AppendAckFrameFromBitmap(payload, 0, ackLast, ackBitmap)
	}
	if len(pendingCrypto) > 0 {
		payload = transport.AppendCryptoFrame(payload, cryptoOff, pendingCrypto)
	}

	c.mu.Lock()
	c.cryptoSent[lvl] += uint64(len(pendingCrypto))
	c.cryptoBuf[lvl] = c.cryptoBuf[lvl][:0]
	c.ackPending[lvl] = false
	c.pn[lvl] = pn + 1
	c.mu.Unlock()

	switch lvl {
	case levelInitial:
		pkt, err := transport.BuildLongHeader(
			transport.LongPacketTypeInitial, transport.QUICv1,
			c.dcid, c.scid, nil, uint32(pn), payload, 1200, pp)
		if err != nil {
			return err
		}
		dbg("send Initial pn=%d crypto=%d ack=%v dcid=%x scid=%x len=%d",
			pn, len(pendingCrypto), ackPending, c.dcid, c.scid, len(pkt))
		_, err = c.pconn.WriteTo(pkt, c.remote)
		return err
	case levelHandshake:
		pkt, err := transport.BuildLongHeader(
			transport.LongPacketTypeHandshake, transport.QUICv1,
			c.dcid, c.scid, nil, uint32(pn), payload, 0, pp)
		if err != nil {
			return err
		}
		dbg("send Handshake pn=%d crypto=%d ack=%v len=%d",
			pn, len(pendingCrypto), ackPending, len(pkt))
		_, err = c.pconn.WriteTo(pkt, c.remote)
		return err
	case levelApp:
		c.mu.Lock()
		phase := c.sendKeyPhase
		c.mu.Unlock()
		pkt, err := transport.BuildShortHeader(c.sendDCID(), uint32(pn), payload, phase, pp)
		if err != nil {
			return err
		}
		dbg("send 1-RTT pn=%d crypto=%d ack=%v len=%d",
			pn, len(pendingCrypto), ackPending, len(pkt))
		_, err = c.pconn.WriteTo(pkt, c.remote)
		return err
	}
	return errors.New("mirage/client: unsupported level for flush")
}

// processDatagram walks all coalesced packets in d, decrypts each with
// the appropriate read protection, and feeds CRYPTO data to uTLS.
func (c *Conn) processDatagram(d []byte) error {
	dbg("recv datagram len=%d", len(d))
	now := time.Now()
	if c.pingClock != nil {
		c.pingClock.Activity(now)
	}
	if c.padder != nil {
		c.padder.AppActivity(now)
	}
	for len(d) > 0 {
		first := d[0]
		isLong := first&0x80 != 0

		if isLong {
			if len(d) < 5 {
				return nil
			}
			t := transport.LongPacketType((first & 0x30) >> 4)
			var lvl encryptionLevel
			switch t {
			case transport.LongPacketTypeInitial:
				lvl = levelInitial
			case transport.LongPacketTypeHandshake:
				lvl = levelHandshake
			default:
				return nil
			}
			c.mu.Lock()
			pp := c.pp[lvl].read
			c.mu.Unlock()
			if pp == nil {
				return nil
			}
			pkt, err := transport.ParseLongHeader(d, pp)
			if err != nil {
				return fmt.Errorf("mirage/client: parse long header (level %d): %w", lvl, err)
			}
			if lvl == levelInitial {
				c.adoptServerDCID(pkt.SCID)
			}
			if err := c.handlePacket(lvl, pkt.PacketNumber, pkt.Payload); err != nil {
				return err
			}
			d = d[pkt.PacketLen:]
			continue
		}

		c.mu.Lock()
		pp := c.pp[levelApp].read
		next := c.appNextRead
		phase := c.recvKeyPhase
		c.mu.Unlock()
		if pp == nil {
			return nil
		}
		pkt, usedNext, err := transport.ParseShortHeaderWithUpdate(d, len(c.scid), pp, next, phase)
		if err != nil {
			// 1-RTT AEAD/parse failures are recoverable: a single
			// corrupted or reordered datagram should not kill an
			// otherwise healthy connection. Count it and discard
			// every byte left in this datagram (we cannot reliably
			// re-frame a partially decrypted coalesced packet).
			c.aeadDrops.Add(1)
			dbg("recv 1-RTT decode failed: %v (drop %d bytes)", err, len(d))
			return nil
		}
		if usedNext {
			if err := c.rotateAppKeys(); err != nil {
				return fmt.Errorf("mirage/client: rotate app keys: %w", err)
			}
		}
		if err := c.handlePacket(levelApp, pkt.PacketNumber, pkt.Payload); err != nil {
			return err
		}
		d = d[pkt.PacketLen:]
	}
	return nil
}

// rotateAppKeys promotes the pre-derived next-phase 1-RTT keys to be
// the current keys, in both directions, and re-derives the next
// next-phase keys from the now-current secrets. RFC 9001 §6.1
// requires the responder to update its send keys "in response" to a
// peer-initiated key update, so both directions flip together. The
// header protection key is kept unchanged.
func (c *Conn) rotateAppKeys() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.appNextRead == nil || c.appNextWrite == nil {
		return errors.New("mirage/client: key update without prepared next keys")
	}
	suite := c.cipherSuite
	newReadSecret, err := transport.NextAppSecret(suite, c.appReadSecret)
	if err != nil {
		return err
	}
	newWriteSecret, err := transport.NextAppSecret(suite, c.appWriteSecret)
	if err != nil {
		return err
	}
	c.pp[levelApp].read = c.appNextRead
	c.pp[levelApp].write = c.appNextWrite
	c.appReadSecret = newReadSecret
	c.appWriteSecret = newWriteSecret
	c.recvKeyPhase = !c.recvKeyPhase
	c.sendKeyPhase = !c.sendKeyPhase

	nextNextRead, err := transport.NextAppSecret(suite, newReadSecret)
	if err != nil {
		return err
	}
	nextNextWrite, err := transport.NextAppSecret(suite, newWriteSecret)
	if err != nil {
		return err
	}
	nextRead, err := transport.RekeyForUpdate(suite, c.pp[levelApp].read, nextNextRead)
	if err != nil {
		return err
	}
	nextWrite, err := transport.RekeyForUpdate(suite, c.pp[levelApp].write, nextNextWrite)
	if err != nil {
		return err
	}
	c.appNextRead = nextRead
	c.appNextWrite = nextWrite
	dbg("1-RTT key update: phase=%v", c.recvKeyPhase)
	return nil
}

func (c *Conn) handlePacket(lvl encryptionLevel, pn uint64, payload []byte) error {
	c.mu.Lock()
	c.ackPending[lvl] = true
	if c.recvWindow[lvl] == nil {
		c.recvWindow[lvl] = replay.NewSlidingWindow(64)
	}
	c.recvWindow[lvl].Check(pn)
	c.mu.Unlock()

	if lvl == levelApp {
		c.wakeSender()
	}

	frames, err := transport.ParseFrames(payload)
	if err != nil {
		return fmt.Errorf("mirage/client: parse frames at level %d: %w", lvl, err)
	}
	dbg("level=%d pn=%d frames=%d", lvl, pn, len(frames))
	for _, f := range frames {
		switch fr := f.(type) {
		case transport.CryptoFrame:
			if err := c.deliverCrypto(lvl, fr.Offset, fr.Data); err != nil {
				return err
			}
		case transport.HandshakeDoneFrame:
			c.handshakeDone.Store(true)
		case transport.ConnectionCloseFrame:
			return fmt.Errorf("mirage/client: peer closed: code=0x%x reason=%q", fr.ErrorCode, fr.Reason)
		case transport.AckFrame:
			if lvl == levelApp {
				c.processAppAck(fr)
			}
		case transport.StreamFrame:
			if lvl == levelApp {
				c.handleStreamFrame(fr)
			}
		case transport.MaxDataFrame:
			if lvl == levelApp {
				c.handleMaxData(fr.Maximum)
			}
		case transport.MaxStreamDataFrame:
			if lvl == levelApp {
				c.handleMaxStreamData(fr.StreamID, fr.Maximum)
			}
		case transport.ResetStreamFrame:
			if lvl == levelApp {
				c.handleResetStream(fr.StreamID, fr.ErrorCode, fr.FinalSize)
			}
		case transport.StopSendingFrame:
			if lvl == levelApp {
				c.handleStopSending(fr.StreamID, fr.ErrorCode)
			}
		case transport.NewConnectionIDFrame:
			if lvl == levelApp {
				c.handleNewConnectionID(fr)
			}
		case transport.PingFrame, transport.PaddingFrame,
			transport.NewTokenFrame:
		}
	}
	return nil
}

// handleMaxData ratchets the connection-level send credit upward and
// wakes the sender if the window grew. Per RFC 9000 §19.9 a smaller
// or equal value is silently ignored.
func (c *Conn) handleMaxData(maximum uint64) {
	c.flowMu.Lock()
	grew := maximum > c.flowConnMaxData
	if grew {
		c.flowConnMaxData = maximum
	}
	c.flowMu.Unlock()
	dbg("recv MAX_DATA max=%d grew=%v", maximum, grew)
	if grew {
		c.wakeSender()
	}
}

// handleMaxStreamData ratchets the per-stream send credit and wakes
// the sender if it grew. Frames for streams we have not opened yet
// are tracked by lookupOrCreate so the credit is preserved for when
// the stream is first used.
func (c *Conn) handleMaxStreamData(id, maximum uint64) {
	if c.streams == nil {
		return
	}
	s := c.streams.lookupOrCreate(id)
	if s.raiseSendMaxData(maximum) {
		dbg("recv MAX_STREAM_DATA id=%d max=%d (raised)", id, maximum)
		c.wakeSender()
	}
}

// handleStreamFrame routes incoming STREAM data to the matching stream,
// creating it if the peer is initiating it.
func (c *Conn) handleStreamFrame(fr transport.StreamFrame) {
	if c.streams == nil {
		return
	}
	dbg("recv STREAM id=%d off=%d len=%d fin=%v", fr.StreamID, fr.Offset, len(fr.Data), fr.Fin)
	s := c.streams.lookupOrCreate(fr.StreamID)
	s.deliver(fr.Offset, fr.Data, fr.Fin)
	c.wakeSender()
}

// handleResetStream marks a stream's receive side as terminally
// failed. Any pending Read returns *StreamError.
func (c *Conn) handleResetStream(streamID, errorCode, finalSize uint64) {
	if c.streams == nil {
		return
	}
	dbg("recv RESET_STREAM id=%d code=0x%x final=%d", streamID, errorCode, finalSize)
	s := c.streams.lookupOrCreate(streamID)
	s.closeRecvWithError(&StreamError{
		Code:   errorCode,
		Local:  false,
		Reason: "stream reset by peer",
	})
}

// handleStopSending marks a stream's send side as cancelled by the
// peer and queues the matching RESET_STREAM in response (RFC 9000
// §3.5).
func (c *Conn) handleStopSending(streamID, errorCode uint64) {
	if c.streams == nil {
		return
	}
	dbg("recv STOP_SENDING id=%d code=0x%x", streamID, errorCode)
	s := c.streams.lookupOrCreate(streamID)
	s.sendMu.Lock()
	finalSize := s.sendOff
	already := s.sendErr != nil
	if !already {
		s.sendErr = &StreamError{
			Code:   errorCode,
			Local:  false,
			Reason: "stop sending requested by peer",
		}
		s.sendBuf = nil
		s.sendClosed = true
		s.finPending = false
		s.sendCond.Broadcast()
	}
	s.sendMu.Unlock()
	if !already {
		c.queueResetStream(streamID, errorCode, finalSize)
	}
}

// processAppAck removes acknowledged 1-RTT packets from the in-flight
// table, folds an RTT sample from the largest acked packet (RFC 9002
// §5.1), runs RFC 9002 §6.1 loss detection on the remaining
// outstanding packets, and reports the combined ack/loss batch to
// the congestion controller in a single OnCongestionEvent call.
func (c *Conn) processAppAck(ack transport.AckFrame) {
	acked := ackedPacketNumbers(ack)
	if len(acked) == 0 {
		return
	}
	now := time.Now()

	c.sentMu.Lock()
	priorBytesInFlight := c.bytesInFlight
	ccAcks := make([]congestion.AckedPacket, 0, len(acked))
	var rttSample time.Duration
	if sentAt, ok := c.sentTimes[ack.LargestAcked]; ok {
		// RFC 9002 §5.1: sample is computed from the largest
		// acknowledged packet number — regardless of whether it
		// was ack-eliciting on our side. Tracking sentTimes for
		// every packet (including ack-only) avoids a race where
		// the trailing ack-only packet ends up as the largest
		// acked and we'd otherwise drop the sample.
		rttSample = now.Sub(sentAt)
	}
	var newLargestAcked uint64
	var newLargestSentAt time.Time
	var sawLargest bool
	for _, pn := range acked {
		delete(c.sentTimes, pn)
		// Check if this was a PMTU probe and confirm the size.
		if probeSize, isProbe := c.pmtuProbes[pn]; isProbe {
			if c.pmtuSearch != nil {
				c.pmtuSearch.Confirmed(probeSize)
			}
			delete(c.pmtuProbes, pn)
		}
		sp, ok := c.sent[pn]
		if !ok {
			continue
		}
		if !sawLargest || pn > newLargestAcked {
			newLargestAcked = pn
			newLargestSentAt = sp.sentAt
			sawLargest = true
		}
		ccAcks = append(ccAcks, congestion.AckedPacket{
			PacketNumber: congestion.PacketNumber(pn),
			BytesAcked:   sp.size,
			SentTime:     sp.sentAt,
			ReceivedTime: now,
		})
		if c.bytesInFlight >= sp.size {
			c.bytesInFlight -= sp.size
		} else {
			c.bytesInFlight = 0
		}
		delete(c.sent, pn)
	}

	if sawLargest && (!c.hasLargestAcked || newLargestAcked > c.largestAckedPN) {
		c.largestAckedPN = newLargestAcked
		c.largestAckedSentAt = newLargestSentAt
		c.hasLargestAcked = true
	}

	var ccLosses []congestion.LostPacket
	if c.hasLargestAcked {
		ccLosses = c.detectLossesLocked(now)
	}
	c.sentMu.Unlock()

	if rttSample > 0 && rttSample < time.Second {
		c.rtt.UpdateRTT(rttSample, c.peerAckDelay(ack.AckDelay))
	}
	if len(ccLosses) > 0 {
		c.wakeSender()
	}
	if (len(ccAcks) > 0 || len(ccLosses) > 0) && c.cc != nil {
		c.cc.OnCongestionEvent(now, priorBytesInFlight, ccAcks, ccLosses)
	}
}

// detectLossesLocked scans c.sent for packets that meet either the
// packet-threshold or the time-threshold rule from RFC 9002 §6.1, moves
// them to c.lostQueue for retransmission, and returns the matching
// congestion.LostPacket records so the caller can report them to the
// congestion controller.
//
// The caller must hold c.sentMu and have updated c.largestAckedPN /
// c.largestAckedSentAt for the current ack batch.
func (c *Conn) detectLossesLocked(now time.Time) []congestion.LostPacket {
	const kPacketThreshold uint64 = 3
	// kTimeThreshold = 9/8 per RFC 9002 §6.1.2; kGranularity = 1 ms.
	const kGranularity = time.Millisecond

	largest := c.largestAckedPN
	latest := c.rtt.LatestRTT()
	smoothed := c.rtt.SmoothedRTT()
	rttRef := smoothed
	if latest > rttRef {
		rttRef = latest
	}
	lossDelay := rttRef + rttRef/8
	if lossDelay < kGranularity {
		lossDelay = kGranularity
	}
	lostSendCutoff := now.Add(-lossDelay)

	var lost []congestion.LostPacket
	for pn, sp := range c.sent {
		if pn >= largest {
			continue
		}
		// Packet-threshold: any packet sent kPacketThreshold or more
		// before the largest ack'd is declared lost.
		gapHit := largest >= kPacketThreshold && pn <= largest-kPacketThreshold
		// Time-threshold: a packet sent before the largest ack'd, and
		// older than the loss-delay window, is declared lost.
		timeHit := !sp.sentAt.After(lostSendCutoff)
		if !gapHit && !timeHit {
			continue
		}
		lost = append(lost, congestion.LostPacket{
			PacketNumber: congestion.PacketNumber(pn),
			BytesLost:    sp.size,
		})
		if c.bytesInFlight >= sp.size {
			c.bytesInFlight -= sp.size
		} else {
			c.bytesInFlight = 0
		}
		delete(c.sent, pn)
		delete(c.sentTimes, pn)
		delete(c.pmtuProbes, pn)
		c.lostQueue = append(c.lostQueue, sp)
	}
	return lost
}

// peerAckDelay decodes the AckDelay field from the peer using its
// advertised ack_delay_exponent (default 3 per RFC 9000 §18.2). It
// returns 0 if the peer's transport parameters have not yet been
// parsed.
func (c *Conn) peerAckDelay(encoded uint64) time.Duration {
	exp := uint64(3)
	if c.serverTP != nil && c.serverTP.AckDelayExponent != 0 {
		exp = c.serverTP.AckDelayExponent
	}
	if exp > 20 {
		// Per RFC 9000 §18.2 the exponent is at most 20; anything
		// larger is the peer's bug, treat as no info.
		return 0
	}
	return time.Duration(encoded<<exp) * time.Microsecond
}

func ackedPacketNumbers(ack transport.AckFrame) []uint64 {
	largest := ack.LargestAcked
	out := make([]uint64, 0, 1+len(ack.Ranges))
	if ack.FirstAckLen > largest {
		return nil
	}
	smallest := largest - ack.FirstAckLen
	for n := smallest; n <= largest; n++ {
		out = append(out, n)
	}
	cursor := smallest
	for _, r := range ack.Ranges {
		gap := r.Gap + 1
		if gap+1 > cursor {
			break
		}
		cursor -= gap + 1
		ackLen := r.AckLen
		if ackLen > cursor {
			ackLen = cursor
		}
		for n := cursor - ackLen; n <= cursor; n++ {
			out = append(out, n)
		}
		if ackLen+1 > cursor {
			break
		}
		cursor -= ackLen + 1
	}
	return out
}

func (c *Conn) deliverCrypto(lvl encryptionLevel, offset uint64, data []byte) error {
	c.mu.Lock()
	if c.cryptoRecvBuf[lvl] == nil {
		c.cryptoRecvBuf[lvl] = make(map[uint64][]byte)
	}
	c.cryptoRecvBuf[lvl][offset] = append([]byte(nil), data...)
	expected := c.cryptoRecvd[lvl]
	var ordered []byte
	for {
		chunk, ok := c.cryptoRecvBuf[lvl][expected]
		if !ok {
			break
		}
		ordered = append(ordered, chunk...)
		delete(c.cryptoRecvBuf[lvl], expected)
		expected += uint64(len(chunk))
	}
	c.cryptoRecvd[lvl] = expected
	c.mu.Unlock()

	if len(ordered) == 0 {
		return nil
	}
	utlsLevel := levelToUTLS(lvl)
	if err := c.utlsConn.HandleData(utlsLevel, ordered); err != nil {
		return fmt.Errorf("mirage/client: uTLS HandleData: %w", err)
	}
	return nil
}

// adoptServerDCID sets c.dcid to the SCID chosen by the server in its
// first response, per RFC 9000 §7.2. It is a no-op once dcid has been
// adopted (subsequent server Initials carry the same SCID).
// handleNewConnectionID admits a peer-issued NEW_CONNECTION_ID into
// the CID pool, honouring retire_prior_to. Any retirements the pool
// records as a side effect are drained on the next flushApp pass via
// drainPendingRetire, so the corresponding RETIRE_CONNECTION_ID
// frames go on the very next outgoing packet.
func (c *Conn) handleNewConnectionID(f transport.NewConnectionIDFrame) {
	if c.cids == nil {
		return
	}
	c.cids.addNew(f)
	c.wakeSender()
}

// maybeRotateCID pops a fresh DCID off the pool and uses it for
// subsequent packets when the configured rotation interval has
// elapsed and at least one idle CID is available. The retired
// sequence number is queued as a RETIRE_CONNECTION_ID frame for the
// next flushApp pass.
func (c *Conn) maybeRotateCID(now time.Time) {
	if c.cids == nil {
		return
	}
	bh := behavior.Default()
	if c.cfg != nil {
		bh = c.cfg.effectiveBehavior()
	}
	if bh.CIDRotateInterval <= 0 {
		return
	}
	if now.Sub(c.lastCIDRotate) < bh.CIDRotateInterval {
		return
	}
	if _, rotated := c.cids.voluntaryRotate(); !rotated {
		return
	}
	c.lastCIDRotate = now
}

// sendDCID returns a snapshot of the connection ID we are currently
// authorised to put on outgoing packet headers. Once 1-RTT keys are
// up the value can change at any time (NEW_CONNECTION_ID + retire,
// or voluntary rotation), so callers MUST NOT cache the result
// across packet boundaries.
func (c *Conn) sendDCID() []byte {
	if c.cids != nil {
		if cid := c.cids.currentDCID(); cid != nil {
			return cid
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.dcid...)
}

func (c *Conn) adoptServerDCID(scid []byte) {
	if len(scid) == 0 {
		return
	}
	c.mu.Lock()
	if c.serverDCIDAdopted {
		c.mu.Unlock()
		return
	}
	c.dcid = append(c.dcid[:0], scid...)
	c.serverDCIDAdopted = true
	c.mu.Unlock()
	if c.cids != nil {
		c.cids.setBootstrap(scid)
	}
}

func levelToUTLS(l encryptionLevel) utls.QUICEncryptionLevel {
	switch l {
	case levelInitial:
		return utls.QUICEncryptionLevelInitial
	case levelEarly:
		return utls.QUICEncryptionLevelEarly
	case levelHandshake:
		return utls.QUICEncryptionLevelHandshake
	case levelApp:
		return utls.QUICEncryptionLevelApplication
	}
	return utls.QUICEncryptionLevelInitial
}

// flushAll attempts to send any pending data at every level that has
// write protection installed.
func (c *Conn) flushAll() error {
	for _, lvl := range [...]encryptionLevel{levelInitial, levelHandshake, levelApp} {
		if err := c.flushLevel(lvl); err != nil {
			return err
		}
	}
	return nil
}

// progress runs one iteration of the handshake loop: pump uTLS events,
// flush any pending data, then return. Callers schedule it on a small
// timer to drive the handshake forward in the absence of incoming data.
func (c *Conn) progress() error {
	if err := c.pumpEvents(); err != nil {
		return err
	}
	return c.flushAll()
}

// driveHandshakeLoop replaces the placeholder in conn.go and runs until
// the handshake completes, the context expires, or the read loop fails.
func (c *Conn) driveHandshakeLoop(deadline time.Time) error {
	tick := time.NewTicker(2 * time.Millisecond)
	defer tick.Stop()
	for !c.handshakeDone.Load() {
		if e := c.loadReadErr(); e != nil {
			return fmt.Errorf("mirage/client: read loop: %w", e)
		}
		if !time.Now().Before(deadline) {
			return errors.New("mirage/client: handshake timeout")
		}
		if err := c.progress(); err != nil {
			return err
		}
		<-tick.C
	}
	return c.progress()
}

// senderLoop owns 1-RTT outbound: it packetises pending stream data,
// emits ACKs for inbound 1-RTT packets, and retransmits stream frames
// whose carrier packet was not ACKed in time. The loop is driven by
// the congestion controller's pacer: when the controller asks for a
// delay before the next send, the loop sleeps for exactly that long
// (or until something interesting happens on wakeCh / stopCh).
func (c *Conn) senderLoop() {
	defer c.wg.Done()
	pingTick := time.NewTicker(time.Second)
	defer pingTick.Stop()
	pacingTimer := time.NewTimer(time.Hour)
	if !pacingTimer.Stop() {
		<-pacingTimer.C
	}
	defer pacingTimer.Stop()
	for {
		if c.closed.Load() {
			return
		}
		if err := c.flushApp(); err != nil {
			c.storeReadErr(err)
			return
		}
		if err := c.retransmitApp(); err != nil {
			c.storeReadErr(err)
			return
		}
		if err := c.maybeSendPing(time.Now()); err != nil {
			c.storeReadErr(err)
			return
		}
		if err := c.maybeSendPadding(time.Now()); err != nil {
			c.storeReadErr(err)
			return
		}
		if err := c.maybeSendPMTUProbe(time.Now()); err != nil {
			c.storeReadErr(err)
			return
		}
		c.maybeRotateCID(time.Now())

		// Default fallback wake interval; lets us re-check timers
		// (retransmit RTO, PING, padding, PMTU probes) without hot-spinning.
		wait := 20 * time.Millisecond
		if c.cc != nil {
			if d := c.cc.TimeUntilSend(time.Now()); d > 0 && d < wait {
				wait = d
			}
		}
		pacingTimer.Reset(wait)

		select {
		case <-c.stopCh:
			if !pacingTimer.Stop() {
				<-pacingTimer.C
			}
			return
		case <-c.wakeCh:
			if !pacingTimer.Stop() {
				<-pacingTimer.C
			}
		case <-pacingTimer.C:
		case <-pingTick.C:
			if !pacingTimer.Stop() {
				<-pacingTimer.C
			}
		}
	}
}

// maybeSendPing emits a single 1-RTT packet carrying one PING frame
// when the behavior PingClock reports the connection has been idle
// past Chrome's PING interval. Issuing PING from the data plane keeps
// the inter-arrival distribution close to a real Chrome flow's
// keepalive cadence.
func (c *Conn) maybeSendPing(now time.Time) error {
	if c.pingClock == nil || !c.pingClock.ShouldPing(now) {
		return nil
	}
	c.mu.Lock()
	pp := c.pp[levelApp].write
	c.mu.Unlock()
	if pp == nil {
		return nil
	}

	c.mu.Lock()
	pn := c.pn[levelApp]
	c.pn[levelApp] = pn + 1
	phase := c.sendKeyPhase
	c.mu.Unlock()

	payload := transport.AppendPingFrame(nil)
	pkt, err := transport.BuildShortHeader(c.sendDCID(), uint32(pn), payload, phase, pp)
	if err != nil {
		return err
	}
	priorInFlight := c.snapshotBytesInFlight()
	if _, err := c.pconn.WriteTo(pkt, c.remote); err != nil {
		return err
	}
	c.notePacketSent(now, pn, congestion.ByteCount(len(pkt)), priorInFlight, true, nil)
	c.pingClock.Activity(now)
	dbg("send PING pn=%d size=%d", pn, len(pkt))
	return nil
}

// maybeSendPadding emits a single 1-RTT packet carrying only PADDING
// frames when the padder says it's time. Padding is injected during
// application idle + BBR ProbeRTT to break the "silent then burst"
// pattern that distinguishes proxy flows from real Chrome traffic.
func (c *Conn) maybeSendPadding(now time.Time) error {
	if c.padder == nil {
		return nil
	}
	// Update BBR-allow gate: padding only fires during ProbeRTT so we
	// don't distort BBR's bandwidth estimate during throughput phases.
	if cc, ok := c.cc.(*bbr2.Controller); ok {
		c.padder.SetBBRAllow(cc.InProbeRTT())
	}

	payload, err := c.padder.Tick(now)
	if err != nil || payload == nil {
		return err
	}

	c.mu.Lock()
	pp := c.pp[levelApp].write
	c.mu.Unlock()
	if pp == nil {
		return nil
	}

	c.mu.Lock()
	pn := c.pn[levelApp]
	c.pn[levelApp] = pn + 1
	phase := c.sendKeyPhase
	c.mu.Unlock()

	pkt, err := transport.BuildShortHeader(c.sendDCID(), uint32(pn), payload, phase, pp)
	if err != nil {
		return err
	}
	priorInFlight := c.snapshotBytesInFlight()
	if _, err := c.pconn.WriteTo(pkt, c.remote); err != nil {
		return err
	}
	c.notePacketSent(now, pn, congestion.ByteCount(len(pkt)), priorInFlight, false, nil)
	dbg("send PADDING pn=%d size=%d payload=%d", pn, len(pkt), len(payload))
	return nil
}

// maybeSendPMTUProbe sends a PING packet padded to the probe size when
// the PMTUSearch says it's time to probe. When the probe is acknowledged,
// processAppAck calls pmtuSearch.Confirmed to record the successful size.
func (c *Conn) maybeSendPMTUProbe(now time.Time) error {
	if c.pmtuSearch == nil || !c.pmtuSearch.ShouldProbe(now) {
		return nil
	}
	probeSize := c.pmtuSearch.NextProbeSize()
	if probeSize == 0 {
		return nil
	}

	c.mu.Lock()
	pp := c.pp[levelApp].write
	c.mu.Unlock()
	if pp == nil {
		return nil
	}

	c.mu.Lock()
	pn := c.pn[levelApp]
	c.pn[levelApp] = pn + 1
	phase := c.sendKeyPhase
	c.mu.Unlock()

	// Build a PING frame and pad to fill the remaining space.
	payload := transport.AppendPingFrame(nil)
	pkt, err := transport.BuildShortHeader(c.sendDCID(), uint32(pn), payload, phase, pp)
	if err != nil {
		return err
	}

	// The packet is currently at minimum size. We need to expand payload
	// so the final packet reaches probeSize. Calculate required padding.
	overhead := len(pkt) - len(payload)
	wantPayload := int(probeSize) - overhead
	if wantPayload > len(payload) {
		// Add PADDING frames to reach the target size.
		padding := make([]byte, wantPayload-len(payload))
		payload = append(payload, padding...)
		pkt, err = transport.BuildShortHeader(c.sendDCID(), uint32(pn), payload, phase, pp)
		if err != nil {
			return err
		}
	}

	priorInFlight := c.snapshotBytesInFlight()
	if _, err := c.pconn.WriteTo(pkt, c.remote); err != nil {
		return err
	}

	// Record this as a PMTU probe so we can confirm on ACK.
	c.sentMu.Lock()
	c.pmtuProbes[pn] = uint16(len(pkt))
	c.sentMu.Unlock()

	c.notePacketSent(now, pn, congestion.ByteCount(len(pkt)), priorInFlight, true, nil)
	c.pmtuSearch.Sent(uint16(len(pkt)), now)
	dbg("send PMTU probe pn=%d size=%d", pn, len(pkt))
	return nil
}

// flushApp emits as many 1-RTT packets as needed to drain pending
// stream data and any pending ACK, subject to the congestion
// controller's permission to send. Each STREAM frame is bounded so we
// stay within the path MTU. When the controller refuses sending or
// when the sender has nothing left to do, flushApp returns and the
// caller (senderLoop) sleeps until either wakeCh fires or the pacing
// timer expires.
func (c *Conn) flushApp() error {
	c.mu.Lock()
	pp := c.pp[levelApp].write
	c.mu.Unlock()
	if pp == nil {
		return nil
	}

	for {
		priorInFlight := c.snapshotBytesInFlight()
		if c.cc != nil {
			if !c.cc.CanSend(priorInFlight) {
				return nil
			}
		}

		streams := c.streams.snapshot()
		var sframes []sentStreamFrame
		var payload []byte

		c.mu.Lock()
		ackPending := c.ackPending[levelApp]
		var ackLast, ackBitmap uint64
		var ackSeeded bool
		if ackPending && c.recvWindow[levelApp] != nil {
			ackLast, ackBitmap, ackSeeded = c.recvWindow[levelApp].Snapshot()
		}
		c.mu.Unlock()
		if ackSeeded {
			payload = transport.AppendAckFrameFromBitmap(payload, 0, ackLast, ackBitmap)
		}

		// Emit any pending MAX_STREAM_DATA / RESET_STREAM /
		// STOP_SENDING frames queued by stream-side helpers. These
		// are tiny, drain unconditionally, and do not consume the
		// connection-level send credit.
		c.flowMu.Lock()
		for streamID, maxData := range c.pendingMaxStreamData {
			payload = transport.AppendMaxStreamDataFrame(payload, streamID, maxData)
			delete(c.pendingMaxStreamData, streamID)
		}
		for streamID, p := range c.pendingResetStream {
			payload = transport.AppendResetStreamFrame(payload, streamID, p.ErrorCode, p.FinalSize)
			delete(c.pendingResetStream, streamID)
		}
		for streamID, ec := range c.pendingStopSending {
			payload = transport.AppendStopSendingFrame(payload, streamID, ec)
			delete(c.pendingStopSending, streamID)
		}
		c.flowMu.Unlock()

		// Drain any RETIRE_CONNECTION_ID frames the CID pool has
		// queued (peer-issued retire_prior_to or our own voluntary
		// rotation). Sequence numbers go out in FIFO order; the
		// payload may contain only retires (no streams), in which
		// case we still send the packet so the peer learns the CIDs
		// have been released.
		if c.cids != nil {
			for _, seq := range c.cids.drainPendingRetire() {
				payload = transport.AppendRetireConnectionIDFrame(payload, seq)
			}
		}

		const maxStreamChunk = 1100
		// Snapshot the conn-level credit once per packet. We update
		// it incrementally as we pull chunks from streams so the
		// next stream in the loop sees the residual budget.
		c.flowMu.Lock()
		var connWindow uint64
		if c.flowConnMaxData > c.flowConnSent {
			connWindow = c.flowConnMaxData - c.flowConnSent
		}
		c.flowMu.Unlock()
		for _, s := range streams {
			budget := uint64(maxStreamChunk)
			if budget > connWindow {
				budget = connWindow
			}
			if sw := s.sendWindow(); sw < budget {
				budget = sw
			}
			off, data, fin, ok := s.nextSendChunk(maxStreamChunk, int(budget))
			if !ok {
				continue
			}
			payload = transport.AppendStreamFrame(payload, s.ID(), off, data, fin)
			sframes = append(sframes, sentStreamFrame{
				streamID: s.ID(),
				offset:   off,
				data:     data,
				fin:      fin,
			})
			connWindow -= uint64(len(data))
			c.flowMu.Lock()
			c.flowConnSent += uint64(len(data))
			c.flowMu.Unlock()
			dbg("flushApp: enqueued STREAM id=%d off=%d len=%d fin=%v", s.ID(), off, len(data), fin)
			if len(payload) > 1100 {
				break
			}
			if connWindow == 0 {
				break
			}
		}

		if len(payload) == 0 {
			if c.cc != nil {
				c.cc.OnAppLimited(priorInFlight)
			}
			return nil
		}

		c.mu.Lock()
		pn := c.pn[levelApp]
		c.pn[levelApp] = pn + 1
		c.ackPending[levelApp] = false
		phase := c.sendKeyPhase
		c.mu.Unlock()

		pkt, err := transport.BuildShortHeader(c.sendDCID(), uint32(pn), payload, phase, pp)
		if err != nil {
			return err
		}
		now := time.Now()
		if _, err := c.pconn.WriteTo(pkt, c.remote); err != nil {
			return err
		}
		if c.pingClock != nil {
			c.pingClock.Activity(now)
		}
		if c.padder != nil && len(sframes) > 0 {
			c.padder.AppActivity(now)
		}
		dbg("send 1-RTT pn=%d payload=%d sframes=%d size=%d", pn, len(payload), len(sframes), len(pkt))

		size := congestion.ByteCount(len(pkt))
		retransmittable := len(sframes) > 0
		var sp *sentPacket
		if retransmittable {
			sp = &sentPacket{pn: pn, sentAt: now, size: size, streams: sframes}
		}
		c.notePacketSent(now, pn, size, priorInFlight, retransmittable, sp)

		hasMore := false
		for _, s := range streams {
			if s.hasPendingSend() {
				hasMore = true
				break
			}
		}
		if !hasMore {
			if c.cc != nil {
				c.cc.OnAppLimited(c.snapshotBytesInFlight())
			}
			return nil
		}
	}
}

// snapshotBytesInFlight reads the current in-flight count under
// sentMu. Callers should treat the result as a read-only snapshot.
func (c *Conn) snapshotBytesInFlight() congestion.ByteCount {
	c.sentMu.Lock()
	defer c.sentMu.Unlock()
	return c.bytesInFlight
}

// notePacketSent records bookkeeping for one packet that has just been
// written to the wire. When sp is non-nil the packet is marked
// retransmittable and stored in the sent map for ack/loss processing;
// passing sp == nil records the packet only for congestion control
// purposes (e.g. ack-only datagrams) without scheduling retransmits.
func (c *Conn) notePacketSent(
	now time.Time,
	pn uint64,
	size, priorInFlight congestion.ByteCount,
	retransmittable bool,
	sp *sentPacket,
) {
	c.sentMu.Lock()
	if sp != nil {
		c.sent[pn] = sp
		c.bytesInFlight += size
	}
	c.sentTimes[pn] = now
	c.sentMu.Unlock()
	if c.cc != nil {
		c.cc.OnPacketSent(now, congestion.PacketNumber(pn), size, priorInFlight, retransmittable)
	}
}

// retransmitApp resends any STREAM frames whose carrier packet has
// either been declared lost by the receive-side loss detector
// (lostQueue) or has gone unacked past the current PTO. The PTO path
// is a probe per RFC 9002 §6.2 — it does NOT report packets as lost
// to the congestion controller; true loss is inferred only from
// ACK-range gaps by processAppAck.
func (c *Conn) retransmitApp() error {
	c.mu.Lock()
	pp := c.pp[levelApp].write
	c.mu.Unlock()
	if pp == nil {
		return nil
	}

	now := time.Now()

	const maxRetries = 16

	c.sentMu.Lock()
	pendingLost := c.lostQueue
	c.lostQueue = nil

	for _, sp := range pendingLost {
		if sp.retries >= maxRetries {
			c.sentMu.Unlock()
			return fmt.Errorf("mirage/client: stream retx exhausted on pn %d", sp.pn)
		}
	}

	// PTO probe: pick any packet whose deadline has elapsed and whose
	// sframes have not already been picked up by loss detection. The
	// PTO base mirrors RFC 9002 §6.2.1 (smoothed_rtt + 4*rttvar +
	// max_ack_delay); we fall back to a 100 ms guess before the first
	// sample, then clamp to a [50 ms, 1 s] window.
	pto := c.rtt.PTO()
	if pto == 0 {
		pto = 100 * time.Millisecond
	}
	if pto < 50*time.Millisecond {
		pto = 50 * time.Millisecond
	}
	if pto > time.Second {
		pto = time.Second
	}

	var probes []*sentPacket
	for pn, sp := range c.sent {
		shift := sp.retries
		if shift > 6 {
			shift = 6
		}
		ptoForPacket := pto << shift
		if ptoForPacket > 30*time.Second {
			ptoForPacket = 30 * time.Second
		}
		if now.Sub(sp.sentAt) < ptoForPacket {
			continue
		}
		if sp.retries >= maxRetries {
			c.sentMu.Unlock()
			return fmt.Errorf("mirage/client: stream retx exhausted on pn %d", pn)
		}
		probes = append(probes, sp)
		delete(c.sent, pn)
		delete(c.sentTimes, pn)
		delete(c.pmtuProbes, pn)
		if c.bytesInFlight >= sp.size {
			c.bytesInFlight -= sp.size
		} else {
			c.bytesInFlight = 0
		}
	}
	c.sentMu.Unlock()

	work := append(pendingLost, probes...)
	for _, sp := range work {
		if err := c.resendSentPacket(sp, pp); err != nil {
			return err
		}
	}
	return nil
}

// resendSentPacket re-emits the stream frames carried by sp at a fresh
// packet number. It updates sp's metadata so the new packet replaces
// the old one in subsequent ack/loss bookkeeping.
func (c *Conn) resendSentPacket(sp *sentPacket, pp *transport.PacketProtection) error {
	var payload []byte
	for _, sf := range sp.streams {
		payload = transport.AppendStreamFrame(payload, sf.streamID, sf.offset, sf.data, sf.fin)
	}
	if len(payload) == 0 {
		return nil
	}
	c.mu.Lock()
	pn := c.pn[levelApp]
	c.pn[levelApp] = pn + 1
	phase := c.sendKeyPhase
	c.mu.Unlock()
	pkt, err := transport.BuildShortHeader(c.sendDCID(), uint32(pn), payload, phase, pp)
	if err != nil {
		return err
	}
	now := time.Now()
	preSendInFlight := c.snapshotBytesInFlight()
	if _, err := c.pconn.WriteTo(pkt, c.remote); err != nil {
		return err
	}
	dbg("retx 1-RTT pn=%d (was %d) sframes=%d retry=%d size=%d",
		pn, sp.pn, len(sp.streams), sp.retries+1, len(pkt))
	sp.pn = pn
	sp.sentAt = now
	sp.size = congestion.ByteCount(len(pkt))
	sp.retries++
	c.notePacketSent(now, pn, sp.size, preSendInFlight, true, sp)
	return nil
}
