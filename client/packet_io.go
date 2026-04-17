package client

import (
	"errors"
	"fmt"
	"log"
	"os"
	"sort"
	"time"

	utls "github.com/refraction-networking/utls"
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
	var ackPNs []uint64
	if ackPending {
		ackPNs = c.ackPNsDescLocked(lvl)
	}
	c.mu.Unlock()

	if pp == nil {
		return nil
	}
	if len(pendingCrypto) == 0 && !ackPending {
		return nil
	}

	var payload []byte
	if len(ackPNs) > 0 {
		payload = transport.AppendAckFrameRanges(payload, 0, ackPNs)
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
		pkt, err := transport.BuildShortHeader(c.dcid, uint32(pn), payload, false, pp)
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
		c.mu.Unlock()
		if pp == nil {
			return nil
		}
		pkt, err := transport.ParseShortHeader(d, len(c.scid), pp)
		if err != nil {
			return fmt.Errorf("mirage/client: parse short header: %w", err)
		}
		if err := c.handlePacket(levelApp, pkt.PacketNumber, pkt.Payload); err != nil {
			return err
		}
		d = d[pkt.PacketLen:]
	}
	return nil
}

func (c *Conn) handlePacket(lvl encryptionLevel, pn uint64, payload []byte) error {
	c.mu.Lock()
	if c.largestRecvPN[lvl] < int64(pn) {
		c.largestRecvPN[lvl] = int64(pn)
	}
	c.ackPending[lvl] = true
	if c.recvPNs[lvl] == nil {
		c.recvPNs[lvl] = make(map[uint64]struct{})
	}
	c.recvPNs[lvl][pn] = struct{}{}
	c.pruneRecvPNsLocked(lvl)
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
		case transport.PingFrame, transport.PaddingFrame,
			transport.NewConnectionIDFrame, transport.NewTokenFrame:
		}
	}
	return nil
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

// processAppAck removes acknowledged 1-RTT packets from the in-flight
// table so the retransmit loop stops considering them.
func (c *Conn) processAppAck(ack transport.AckFrame) {
	acked := ackedPacketNumbers(ack)
	if len(acked) == 0 {
		return
	}
	c.sentMu.Lock()
	defer c.sentMu.Unlock()
	for _, pn := range acked {
		if sp, ok := c.sent[pn]; ok {
			rtt := time.Since(sp.sentAt)
			if rtt > 0 && rtt < time.Second {
				if c.rttSRTT == 0 {
					c.rttSRTT = rtt
				} else {
					c.rttSRTT = (c.rttSRTT*7 + rtt) / 8
				}
			}
			delete(c.sent, pn)
		}
	}
}

// pruneRecvPNsLocked drops entries more than 64 packets behind the
// largest received PN at lvl. Callers must hold c.mu. The window keeps
// ACK frames small while still covering the typical reorder horizon.
func (c *Conn) pruneRecvPNsLocked(lvl encryptionLevel) {
	if len(c.recvPNs[lvl]) <= 128 {
		return
	}
	largest := c.largestRecvPN[lvl]
	if largest < 64 {
		return
	}
	cutoff := uint64(largest - 64)
	for pn := range c.recvPNs[lvl] {
		if pn < cutoff {
			delete(c.recvPNs[lvl], pn)
		}
	}
}

// ackPNsDescLocked returns received PNs at lvl sorted largest-first.
// Callers must hold c.mu.
func (c *Conn) ackPNsDescLocked(lvl encryptionLevel) []uint64 {
	out := make([]uint64, 0, len(c.recvPNs[lvl]))
	for pn := range c.recvPNs[lvl] {
		out = append(out, pn)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] > out[j] })
	return out
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
func (c *Conn) adoptServerDCID(scid []byte) {
	if len(scid) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.serverDCIDAdopted {
		return
	}
	c.dcid = append(c.dcid[:0], scid...)
	c.serverDCIDAdopted = true
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
// whose carrier packet was not ACKed in time.
func (c *Conn) senderLoop() {
	defer c.wg.Done()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
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
		select {
		case <-c.stopCh:
			return
		case <-c.wakeCh:
		case <-tick.C:
		}
	}
}

// flushApp emits as many 1-RTT packets as needed to drain pending
// stream data and any pending ACK. Each STREAM frame is bounded so we
// stay within the path MTU.
func (c *Conn) flushApp() error {
	c.mu.Lock()
	pp := c.pp[levelApp].write
	c.mu.Unlock()
	if pp == nil {
		return nil
	}

	for {
		streams := c.streams.snapshot()
		var sframes []sentStreamFrame
		var payload []byte

		c.mu.Lock()
		ackPending := c.ackPending[levelApp]
		var ackPNs []uint64
		if ackPending {
			ackPNs = c.ackPNsDescLocked(levelApp)
		}
		c.mu.Unlock()
		if len(ackPNs) > 0 {
			payload = transport.AppendAckFrameRanges(payload, 0, ackPNs)
		}

		const maxStreamChunk = 1100
		for _, s := range streams {
			off, data, fin, ok := s.nextSendChunk(maxStreamChunk)
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
			dbg("flushApp: enqueued STREAM id=%d off=%d len=%d fin=%v", s.ID(), off, len(data), fin)
			if len(payload) > 1100 {
				break
			}
		}

		if len(payload) == 0 {
			return nil
		}

		c.mu.Lock()
		pn := c.pn[levelApp]
		c.pn[levelApp] = pn + 1
		c.ackPending[levelApp] = false
		c.mu.Unlock()

		pkt, err := transport.BuildShortHeader(c.dcid, uint32(pn), payload, false, pp)
		if err != nil {
			return err
		}
		if _, err := c.pconn.WriteTo(pkt, c.remote); err != nil {
			return err
		}
		dbg("send 1-RTT pn=%d payload=%d sframes=%d", pn, len(payload), len(sframes))

		if len(sframes) > 0 {
			c.sentMu.Lock()
			c.sent[pn] = &sentPacket{pn: pn, sentAt: time.Now(), streams: sframes}
			c.sentMu.Unlock()
		}

		hasMore := false
		for _, s := range streams {
			if s.hasPendingSend() {
				hasMore = true
				break
			}
		}
		if !hasMore {
			return nil
		}
	}
}

// retransmitApp resends any STREAM frames whose carrier packet has
// gone unacked for longer than 4*SRTT (clamped to a sane minimum), up
// to 6 times before giving up on the connection.
func (c *Conn) retransmitApp() error {
	c.mu.Lock()
	pp := c.pp[levelApp].write
	c.mu.Unlock()
	if pp == nil {
		return nil
	}

	c.sentMu.Lock()
	rto := c.rttSRTT * 4
	if rto < 50*time.Millisecond {
		rto = 50 * time.Millisecond
	}
	if rto > time.Second {
		rto = time.Second
	}
	now := time.Now()
	var expired []*sentPacket
	for pn, sp := range c.sent {
		if now.Sub(sp.sentAt) >= rto {
			if sp.retries >= 6 {
				c.sentMu.Unlock()
				return fmt.Errorf("mirage/client: stream retx exhausted on pn %d", pn)
			}
			expired = append(expired, sp)
			delete(c.sent, pn)
		}
	}
	c.sentMu.Unlock()

	for _, sp := range expired {
		var payload []byte
		for _, sf := range sp.streams {
			payload = transport.AppendStreamFrame(payload, sf.streamID, sf.offset, sf.data, sf.fin)
		}
		if len(payload) == 0 {
			continue
		}
		c.mu.Lock()
		pn := c.pn[levelApp]
		c.pn[levelApp] = pn + 1
		c.mu.Unlock()
		pkt, err := transport.BuildShortHeader(c.dcid, uint32(pn), payload, false, pp)
		if err != nil {
			return err
		}
		if _, err := c.pconn.WriteTo(pkt, c.remote); err != nil {
			return err
		}
		dbg("retx 1-RTT pn=%d (was %d) sframes=%d retry=%d",
			pn, sp.pn, len(sp.streams), sp.retries+1)
		sp.pn = pn
		sp.sentAt = now
		sp.retries++
		c.sentMu.Lock()
		c.sent[pn] = sp
		c.sentMu.Unlock()
	}
	return nil
}
