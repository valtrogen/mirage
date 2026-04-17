package client

import (
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

// ErrStreamClosed is returned by Read/Write after the stream has been
// closed locally or by the peer.
var ErrStreamClosed = errors.New("mirage/client: stream closed")

// StreamError is returned by Read or Write when the stream was reset
// or had its read side cancelled. Code is the application-defined
// QUIC error carried in the RESET_STREAM or STOP_SENDING frame.
type StreamError struct {
	Code   uint64
	Local  bool   // true when the local peer initiated the reset
	Reason string // human-readable reason; never empty
}

func (e *StreamError) Error() string {
	side := "remote"
	if e.Local {
		side = "local"
	}
	return "mirage/client: " + side + " " + e.Reason + " code=0x" + hexU64(e.Code)
}

func hexU64(v uint64) string {
	const digits = "0123456789abcdef"
	if v == 0 {
		return "0"
	}
	var buf [16]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = digits[v&0xF]
		v >>= 4
	}
	return string(buf[i:])
}

// Stream is one bidirectional QUIC stream. It implements io.ReadWriter
// and io.Closer; Close shuts down only the send direction (sending FIN),
// the receive direction stays open until the peer FINs or the
// connection drops.
type Stream struct {
	id   uint64
	conn *Conn

	sendMu     sync.Mutex
	sendCond   *sync.Cond
	sendBuf    []byte
	sendOff    uint64
	finSent    bool
	finPending bool
	sendClosed bool
	sendErr    error
	// sendMaxData is the peer's current MAX_STREAM_DATA limit for
	// this stream — the absolute byte offset (RFC 9000 §4.1) up to
	// which we are authorised to send. Initialised from the server's
	// transport parameters (see streamMap.openLocal /
	// streamMap.lookupOrCreate) and ratcheted upwards when
	// MAX_STREAM_DATA frames arrive. The sender treats sendOff
	// reaching sendMaxData as flow-control blocked.
	sendMaxData uint64
	// sendBufCap is the maximum number of bytes that can be held in
	// sendBuf at once. When sendBuf reaches this limit, Write blocks
	// until the sender drains enough data. Zero means no limit.
	sendBufCap int

	recvMu     sync.Mutex
	recvCond   *sync.Cond
	recvBuf    []byte
	recvHead   uint64
	recvOOO    map[uint64][]byte
	recvFinOff uint64
	recvFin    bool
	recvErr    error
	// recvWindow is the receive flow control window size used to
	// calculate when to emit MAX_STREAM_DATA updates. Initialized
	// from our transport parameters when the stream is created.
	recvWindow uint64
	// recvMaxDataAdvertised is the MAX_STREAM_DATA value we have
	// most recently advertised to the peer (or the initial value
	// from transport parameters). When recvHead passes more than
	// half the window past the last advertised limit, we queue a
	// new MAX_STREAM_DATA frame.
	recvMaxDataAdvertised uint64

	deadlineMu  sync.Mutex
	readDeadln  time.Time
	writeDeadln time.Time
}

func newStream(c *Conn, id uint64) *Stream {
	s := &Stream{
		id:      id,
		conn:    c,
		recvOOO: make(map[uint64][]byte),
	}
	s.sendCond = sync.NewCond(&s.sendMu)
	s.recvCond = sync.NewCond(&s.recvMu)
	return s
}

// ID returns the QUIC stream identifier.
func (s *Stream) ID() uint64 { return s.id }

// Write queues p for transmission. It returns once all of p has been
// handed to the conn-level sender; it does not wait for acknowledgement.
// If sendBufCap is set and the buffer is full, Write blocks until the
// sender drains enough data or the write deadline expires.
func (s *Stream) Write(p []byte) (int, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()

	written := 0
	for len(p) > 0 {
		if s.sendErr != nil {
			return written, s.sendErr
		}
		if s.sendClosed || s.finPending {
			return written, ErrStreamClosed
		}

		// Check write deadline.
		if dl := s.writeDeadline(); !dl.IsZero() && !time.Now().Before(dl) {
			return written, os.ErrDeadlineExceeded
		}

		// If buffer has room (or no limit), append what we can.
		if s.sendBufCap == 0 || len(s.sendBuf) < s.sendBufCap {
			room := len(p)
			if s.sendBufCap > 0 && len(s.sendBuf)+room > s.sendBufCap {
				room = s.sendBufCap - len(s.sendBuf)
			}
			s.sendBuf = append(s.sendBuf, p[:room]...)
			p = p[room:]
			written += room
			s.conn.wakeSender()
		}

		// If more data remains and buffer is full, block until drained.
		if len(p) > 0 && s.sendBufCap > 0 && len(s.sendBuf) >= s.sendBufCap {
			s.waitSend()
		}
	}
	return written, nil
}

// writeDeadline returns the current write deadline.
func (s *Stream) writeDeadline() time.Time {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	return s.writeDeadln
}

// waitSend blocks until sendCond is signaled or the watchdog fires.
// Called while holding sendMu.
func (s *Stream) waitSend() {
	timer := time.AfterFunc(50*time.Millisecond, func() {
		s.sendMu.Lock()
		s.sendCond.Broadcast()
		s.sendMu.Unlock()
	})
	s.sendCond.Wait()
	timer.Stop()
}

// Close marks the send side as finished. The next packet carrying
// stream data (or an empty STREAM frame) will set the FIN bit. Close
// does not wait for the peer to acknowledge.
func (s *Stream) Close() error {
	s.sendMu.Lock()
	if s.sendClosed {
		s.sendMu.Unlock()
		return nil
	}
	s.sendClosed = true
	s.finPending = true
	s.sendMu.Unlock()
	s.conn.wakeSender()
	return nil
}

// Reset abandons the send side: the local peer drops any unsent bytes
// and queues a RESET_STREAM frame carrying errorCode. Subsequent Write
// calls return a *StreamError. Reset is idempotent.
func (s *Stream) Reset(errorCode uint64) error {
	s.sendMu.Lock()
	if s.sendErr != nil {
		s.sendMu.Unlock()
		return nil
	}
	finalSize := s.sendOff + uint64(len(s.sendBuf))
	s.sendBuf = nil
	s.sendClosed = true
	s.finPending = false
	s.sendErr = &StreamError{Code: errorCode, Local: true, Reason: "stream reset"}
	s.sendCond.Broadcast()
	s.sendMu.Unlock()
	if s.conn != nil {
		s.conn.queueResetStream(s.id, errorCode, finalSize)
	}
	return nil
}

// CancelRead abandons the receive side: the local peer drops any
// buffered bytes and queues a STOP_SENDING frame carrying errorCode.
// Subsequent Read calls return a *StreamError. The peer is expected to
// respond with RESET_STREAM, which will eventually be observed but is
// not waited for. CancelRead is idempotent.
func (s *Stream) CancelRead(errorCode uint64) error {
	s.recvMu.Lock()
	if s.recvErr != nil {
		s.recvMu.Unlock()
		return nil
	}
	s.recvBuf = nil
	s.recvOOO = nil
	s.recvErr = &StreamError{Code: errorCode, Local: true, Reason: "read cancelled"}
	s.recvCond.Broadcast()
	s.recvMu.Unlock()
	if s.conn != nil {
		s.conn.queueStopSending(s.id, errorCode)
	}
	return nil
}

// Read pulls available data from the stream into p. It blocks until at
// least one byte is available, the stream is closed, the read deadline
// expires, or the underlying connection fails.
func (s *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	for len(s.recvBuf) == 0 {
		if s.recvErr != nil {
			return 0, s.recvErr
		}
		if s.recvFin && s.recvHead >= s.recvFinOff {
			return 0, io.EOF
		}
		if err := s.connError(); err != nil {
			return 0, err
		}
		if dl := s.readDeadline(); !dl.IsZero() && !time.Now().Before(dl) {
			return 0, os.ErrDeadlineExceeded
		}
		s.waitRecv()
	}
	n := copy(p, s.recvBuf)
	s.recvBuf = s.recvBuf[n:]
	s.recvHead += uint64(n)
	s.maybeQueueFlowControlUpdate()
	return n, nil
}

// maybeQueueFlowControlUpdate checks if the application has drained
// enough data to warrant a MAX_STREAM_DATA update to the peer. This
// follows RFC 9000 guidance: we update when we've consumed roughly
// half the advertised window. Called while holding recvMu.
func (s *Stream) maybeQueueFlowControlUpdate() {
	if s.recvWindow == 0 {
		return
	}
	threshold := s.recvMaxDataAdvertised - s.recvWindow/2
	if s.recvHead > threshold {
		newLimit := s.recvHead + s.recvWindow
		if newLimit > s.recvMaxDataAdvertised {
			s.recvMaxDataAdvertised = newLimit
			// Queue the update for the sender to emit.
			if s.conn != nil {
				s.conn.queueMaxStreamData(s.id, newLimit)
			}
		}
	}
}

// SetReadDeadline sets the absolute time after which Read returns
// os.ErrDeadlineExceeded. A zero value disables the deadline.
func (s *Stream) SetReadDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.readDeadln = t
	s.deadlineMu.Unlock()
	s.recvMu.Lock()
	s.recvCond.Broadcast()
	s.recvMu.Unlock()
	return nil
}

// SetWriteDeadline records a write deadline. The current write path
// never blocks (Write only appends to an in-memory buffer), so the
// stored value is observed when flow-control gating lands; until then
// it is accepted for net.Conn compatibility.
func (s *Stream) SetWriteDeadline(t time.Time) error {
	s.deadlineMu.Lock()
	s.writeDeadln = t
	s.deadlineMu.Unlock()
	return nil
}

// SetDeadline sets both read and write deadlines to t.
func (s *Stream) SetDeadline(t time.Time) error {
	if err := s.SetReadDeadline(t); err != nil {
		return err
	}
	return s.SetWriteDeadline(t)
}

func (s *Stream) readDeadline() time.Time {
	s.deadlineMu.Lock()
	defer s.deadlineMu.Unlock()
	return s.readDeadln
}

// connError reports if the owning connection has died. Called while
// holding recvMu.
func (s *Stream) connError() error {
	if s.conn == nil {
		return nil
	}
	if s.conn.closed.Load() {
		return ErrStreamClosed
	}
	if e := s.conn.loadReadErr(); e != nil {
		return e
	}
	return nil
}

// waitRecv blocks until either Stream.deliver broadcasts or the
// 50 ms watchdog fires (so we re-check connError without depending on
// a wakeup we may never get).
func (s *Stream) waitRecv() {
	timer := time.AfterFunc(50*time.Millisecond, func() {
		s.recvMu.Lock()
		s.recvCond.Broadcast()
		s.recvMu.Unlock()
	})
	s.recvCond.Wait()
	timer.Stop()
}

// nextSendChunk is called by the conn sender. It pulls up to
// min(maxLen, streamWindow) bytes from the send buffer and reports
// whether FIN should accompany them. streamWindow is the per-stream
// flow control budget remaining at the conn level (already capped by
// the connection-level credit by the caller). FIN-only frames are
// allowed even when streamWindow is zero, since a FIN consumes no
// flow control credit (RFC 9000 §4.1).
//
// Returns hasFrame=false when there is nothing to send (no data and
// no pending FIN, or the buffer is data-only and the window is fully
// closed).
func (s *Stream) nextSendChunk(maxLen, streamWindow int) (offset uint64, data []byte, fin bool, hasFrame bool) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if len(s.sendBuf) == 0 && !s.finPending {
		return 0, nil, false, false
	}
	off := s.sendOff
	n := len(s.sendBuf)
	if n > maxLen {
		n = maxLen
	}
	if n > streamWindow {
		n = streamWindow
	}
	if n < 0 {
		n = 0
	}
	// Drop the empty / no-progress case: no data left to ship and
	// no FIN that we could emit alone (FIN can only be sent once
	// every queued byte has been packetised, RFC 9000 §3.2).
	if n == 0 && (!s.finPending || len(s.sendBuf) > 0) {
		return 0, nil, false, false
	}
	var chunk []byte
	if n > 0 {
		chunk = append([]byte(nil), s.sendBuf[:n]...)
		s.sendBuf = s.sendBuf[n:]
		s.sendOff += uint64(n)
		// Wake any blocked Write() calls waiting for buffer space.
		s.sendCond.Broadcast()
	}
	finBit := false
	if s.finPending && len(s.sendBuf) == 0 {
		finBit = true
		s.finSent = true
		s.finPending = false
	}
	return off, chunk, finBit, true
}

// hasPendingSend reports whether the stream still has data or a FIN
// flag waiting to be packetised. It does not consider flow control;
// a stream may be pending but blocked on the peer's window.
func (s *Stream) hasPendingSend() bool {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return len(s.sendBuf) > 0 || s.finPending
}

// sendWindow returns the number of additional payload bytes the peer
// has authorised on this stream beyond what we have already sent.
func (s *Stream) sendWindow() uint64 {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.sendOff >= s.sendMaxData {
		return 0
	}
	return s.sendMaxData - s.sendOff
}

// raiseSendMaxData ratchets sendMaxData up to maximum. RFC 9000
// §19.10 requires us to ignore non-monotonic updates rather than
// fail. Returns true when the limit grew (so the caller can wake the
// sender).
func (s *Stream) raiseSendMaxData(maximum uint64) bool {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if maximum <= s.sendMaxData {
		return false
	}
	s.sendMaxData = maximum
	return true
}

// deliver merges an incoming STREAM frame into the receive buffer.
func (s *Stream) deliver(offset uint64, data []byte, fin bool) {
	s.recvMu.Lock()
	defer s.recvMu.Unlock()
	if fin {
		s.recvFin = true
		s.recvFinOff = offset + uint64(len(data))
	}
	if len(data) == 0 {
		s.recvCond.Broadcast()
		return
	}
	end := offset + uint64(len(data))
	if end <= s.recvHead+uint64(len(s.recvBuf)) {
		// Entire chunk already covered.
		s.recvCond.Broadcast()
		return
	}
	if offset < s.recvHead+uint64(len(s.recvBuf)) {
		// Trim leading overlap.
		skip := s.recvHead + uint64(len(s.recvBuf)) - offset
		data = data[skip:]
		offset += skip
	}
	expected := s.recvHead + uint64(len(s.recvBuf))
	if offset == expected {
		s.recvBuf = append(s.recvBuf, data...)
		// Try to drain any out-of-order chunk that fills in.
		for {
			next := s.recvHead + uint64(len(s.recvBuf))
			chunk, ok := s.recvOOO[next]
			if !ok {
				break
			}
			delete(s.recvOOO, next)
			s.recvBuf = append(s.recvBuf, chunk...)
		}
	} else {
		s.recvOOO[offset] = append([]byte(nil), data...)
	}
	s.recvCond.Broadcast()
}

// closeRecvWithError fails any blocked readers with err.
func (s *Stream) closeRecvWithError(err error) {
	s.recvMu.Lock()
	if s.recvErr == nil {
		s.recvErr = err
	}
	s.recvCond.Broadcast()
	s.recvMu.Unlock()
}

// closeSendWithError fails any future writers with err.
func (s *Stream) closeSendWithError(err error) {
	s.sendMu.Lock()
	if s.sendErr == nil {
		s.sendErr = err
	}
	s.sendBuf = nil
	s.sendCond.Broadcast()
	s.sendMu.Unlock()
}
