package client

import (
	"testing"

	"github.com/valtrogen/mirage/transport"
)

// TestStreamSendWindowReportsUnsentCredit verifies that Stream.sendWindow
// reflects the gap between the peer's MAX_STREAM_DATA limit and the
// number of bytes we have already shipped (sendOff). The accounting
// follows RFC 9000 §4.1 — the limit and offset are both absolute.
func TestStreamSendWindowReportsUnsentCredit(t *testing.T) {
	s := newStream(nil, 0)
	s.sendMaxData = 1000

	if got := s.sendWindow(); got != 1000 {
		t.Fatalf("fresh stream window: got %d want %d", got, 1000)
	}

	s.sendOff = 400
	if got := s.sendWindow(); got != 600 {
		t.Fatalf("after 400B sent: got %d want %d", got, 600)
	}

	s.sendOff = 1000
	if got := s.sendWindow(); got != 0 {
		t.Fatalf("at limit: got %d want %d", got, 0)
	}

	// Defensive: if accounting somehow overshoots the limit, we
	// must report zero rather than wrap around (unsigned subtract).
	s.sendOff = 1500
	if got := s.sendWindow(); got != 0 {
		t.Fatalf("over limit: got %d want %d", got, 0)
	}
}

// TestStreamRaiseSendMaxDataIsMonotonic checks RFC 9000 §19.10:
// MAX_STREAM_DATA frames may arrive in any order and the receiver must
// only honour values greater than the current limit.
func TestStreamRaiseSendMaxDataIsMonotonic(t *testing.T) {
	s := newStream(nil, 0)
	s.sendMaxData = 200

	if grew := s.raiseSendMaxData(150); grew {
		t.Fatalf("smaller value should not raise the limit")
	}
	if s.sendMaxData != 200 {
		t.Fatalf("limit changed by smaller value: got %d", s.sendMaxData)
	}

	if grew := s.raiseSendMaxData(200); grew {
		t.Fatalf("equal value should not raise the limit")
	}

	if grew := s.raiseSendMaxData(500); !grew {
		t.Fatalf("larger value should raise the limit")
	}
	if s.sendMaxData != 500 {
		t.Fatalf("limit not raised: got %d want %d", s.sendMaxData, 500)
	}

	if grew := s.raiseSendMaxData(400); grew {
		t.Fatalf("regressing value should be ignored")
	}
	if s.sendMaxData != 500 {
		t.Fatalf("limit regressed: got %d want %d", s.sendMaxData, 500)
	}
}

// TestNextSendChunkRespectsStreamWindow confirms the sender does not
// pull more bytes from the buffer than the per-stream window allows,
// even when maxLen would otherwise admit a bigger chunk.
func TestNextSendChunkRespectsStreamWindow(t *testing.T) {
	s := newStream(nil, 0)
	s.sendMaxData = 100
	s.sendBuf = make([]byte, 1000)

	off, data, fin, ok := s.nextSendChunk(500, 100)
	if !ok {
		t.Fatalf("expected a frame")
	}
	if off != 0 {
		t.Fatalf("offset: got %d want 0", off)
	}
	if len(data) != 100 {
		t.Fatalf("chunk len: got %d want 100", len(data))
	}
	if fin {
		t.Fatalf("fin should not be set with data still buffered")
	}
	if s.sendOff != 100 {
		t.Fatalf("sendOff: got %d want 100", s.sendOff)
	}

	// Window now exhausted; another call must yield no frame even
	// though data remains.
	if _, _, _, ok := s.nextSendChunk(500, 0); ok {
		t.Fatalf("blocked stream should not emit a data frame")
	}
}

// TestNextSendChunkFinAlwaysAllowed exercises RFC 9000 §4.1's "FIN
// consumes no flow-control credit" rule: once the buffer is drained
// we must still be able to ship the bare FIN even when streamWindow
// is zero.
func TestNextSendChunkFinAlwaysAllowed(t *testing.T) {
	s := newStream(nil, 0)
	s.sendMaxData = 0
	s.finPending = true

	off, data, fin, ok := s.nextSendChunk(500, 0)
	if !ok {
		t.Fatalf("FIN-only frame should be allowed")
	}
	if off != 0 || len(data) != 0 || !fin {
		t.Fatalf("got off=%d len=%d fin=%v want 0/0/true", off, len(data), fin)
	}
	if !s.finSent || s.finPending {
		t.Fatalf("finSent=%v finPending=%v want true/false", s.finSent, s.finPending)
	}
}

// TestNextSendChunkNoProgressWhenBufferedAndBlocked verifies that a
// stream which has data buffered AND a pending FIN does NOT emit the
// FIN early. The FIN may only piggyback on the chunk that ships the
// final byte of the buffer, so a 0-byte window must produce no frame.
func TestNextSendChunkNoProgressWhenBufferedAndBlocked(t *testing.T) {
	s := newStream(nil, 0)
	s.sendMaxData = 0
	s.finPending = true
	s.sendBuf = []byte("hi")

	if _, _, _, ok := s.nextSendChunk(500, 0); ok {
		t.Fatalf("must not emit FIN while data is still pending")
	}
	if s.finSent {
		t.Fatalf("finSent prematurely flipped")
	}
}

// TestHandleMaxDataMonotonic checks the connection-level MAX_DATA
// ratchet (RFC 9000 §19.9): smaller / equal values are ignored.
func TestHandleMaxDataMonotonic(t *testing.T) {
	c := &Conn{}
	c.flowConnMaxData = 4096

	c.handleMaxData(2048)
	if c.flowConnMaxData != 4096 {
		t.Fatalf("smaller MAX_DATA modified the limit: got %d", c.flowConnMaxData)
	}

	c.handleMaxData(4096)
	if c.flowConnMaxData != 4096 {
		t.Fatalf("equal MAX_DATA modified the limit: got %d", c.flowConnMaxData)
	}

	c.handleMaxData(8192)
	if c.flowConnMaxData != 8192 {
		t.Fatalf("larger MAX_DATA not honoured: got %d want %d", c.flowConnMaxData, 8192)
	}
}

// TestHandleMaxStreamDataRoutesToStream verifies that an incoming
// MAX_STREAM_DATA frame finds its way to the matching stream and the
// per-stream limit ratchets up. Routing on the receive path is what
// keeps a flow-control-blocked sender unblocked once the peer issues
// fresh credit (RFC 9000 §19.10).
func TestHandleMaxStreamDataRoutesToStream(t *testing.T) {
	c := &Conn{
		serverTP: &transport.TransportParameters{
			InitialMaxStreamDataBidiLocal:  1024,
			InitialMaxStreamDataBidiRemote: 1024,
		},
		wakeCh: make(chan struct{}, 1),
	}
	c.streams = newStreamMap(c)

	s := c.streams.openLocal()
	if s.sendMaxData != 1024 {
		t.Fatalf("openLocal sendMaxData: got %d want 1024", s.sendMaxData)
	}

	c.handleMaxStreamData(s.ID(), 4096)
	if s.sendMaxData != 4096 {
		t.Fatalf("after MAX_STREAM_DATA: got %d want 4096", s.sendMaxData)
	}
	select {
	case <-c.wakeCh:
	default:
		t.Fatalf("sender not woken after window grew")
	}

	// Smaller values are ignored, no wake-up either.
	c.handleMaxStreamData(s.ID(), 2048)
	if s.sendMaxData != 4096 {
		t.Fatalf("regression accepted: got %d want 4096", s.sendMaxData)
	}
	select {
	case <-c.wakeCh:
		t.Fatalf("sender woken on no-op MAX_STREAM_DATA")
	default:
	}
}

// TestStreamMapOpenLocalSeedsFromTransportParams confirms that the
// initial per-stream send window is taken from
// initial_max_stream_data_bidi_remote (RFC 9000 §18.2): for streams
// the client opens, the server's transport parameter dictates how
// many bytes the server is initially willing to receive.
func TestStreamMapOpenLocalSeedsFromTransportParams(t *testing.T) {
	c := &Conn{
		serverTP: &transport.TransportParameters{
			InitialMaxStreamDataBidiRemote: 65536,
		},
	}
	c.streams = newStreamMap(c)

	s := c.streams.openLocal()
	if s.sendMaxData != 65536 {
		t.Fatalf("openLocal sendMaxData: got %d want %d", s.sendMaxData, 65536)
	}

	// A second stream gets the same initial credit; per-stream
	// limits are tracked independently.
	s2 := c.streams.openLocal()
	if s2.sendMaxData != 65536 {
		t.Fatalf("second stream sendMaxData: got %d want %d", s2.sendMaxData, 65536)
	}
	if s.ID() == s2.ID() {
		t.Fatalf("stream IDs must be distinct: got %d twice", s.ID())
	}
}
