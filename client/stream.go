package client

import (
	"errors"
	"io"
	"sync"
	"time"
)

// ErrStreamClosed is returned by Read/Write after the stream has been
// closed locally or by the peer.
var ErrStreamClosed = errors.New("mirage/client: stream closed")

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

	recvMu     sync.Mutex
	recvCond   *sync.Cond
	recvBuf    []byte
	recvHead   uint64
	recvOOO    map[uint64][]byte
	recvFinOff uint64
	recvFin    bool
	recvErr    error

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
func (s *Stream) Write(p []byte) (int, error) {
	s.sendMu.Lock()
	if s.sendErr != nil {
		err := s.sendErr
		s.sendMu.Unlock()
		return 0, err
	}
	if s.sendClosed || s.finPending {
		s.sendMu.Unlock()
		return 0, ErrStreamClosed
	}
	s.sendBuf = append(s.sendBuf, p...)
	s.sendMu.Unlock()
	s.conn.wakeSender()
	return len(p), nil
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

// Read pulls available data from the stream into p. It blocks until at
// least one byte is available, the stream is closed, or the underlying
// connection fails.
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
		s.waitRecv()
	}
	n := copy(p, s.recvBuf)
	s.recvBuf = s.recvBuf[n:]
	s.recvHead += uint64(n)
	return n, nil
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

// nextSendChunk is called by the conn sender. It pulls up to maxLen
// bytes from the send buffer and reports whether FIN should accompany
// them. It returns nil chunk and fin=false when nothing is pending.
func (s *Stream) nextSendChunk(maxLen int) (offset uint64, data []byte, fin bool, hasFrame bool) {
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
	chunk := append([]byte(nil), s.sendBuf[:n]...)
	s.sendBuf = s.sendBuf[n:]
	s.sendOff += uint64(n)
	finBit := false
	if s.finPending && len(s.sendBuf) == 0 {
		finBit = true
		s.finSent = true
		s.finPending = false
	}
	return off, chunk, finBit, true
}

// hasPendingSend reports whether the stream still has data or a FIN
// flag waiting to be packetised.
func (s *Stream) hasPendingSend() bool {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	return len(s.sendBuf) > 0 || s.finPending
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
