package transport

import (
	"bytes"
	"testing"
)

func TestAppendCryptoRoundTrip(t *testing.T) {
	data := []byte("client hello bytes")
	enc := AppendCryptoFrame(nil, 0, data)

	frames, err := ParseFrames(enc)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("len=%d want 1", len(frames))
	}
	cf, ok := frames[0].(CryptoFrame)
	if !ok {
		t.Fatalf("type %T", frames[0])
	}
	if cf.Offset != 0 || !bytes.Equal(cf.Data, data) {
		t.Fatalf("got %+v", cf)
	}
}

func TestAppendCryptoNonZeroOffset(t *testing.T) {
	data := []byte("more crypto")
	enc := AppendCryptoFrame(nil, 16384, data)
	frames, err := ParseFrames(enc)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	cf := frames[0].(CryptoFrame)
	if cf.Offset != 16384 || !bytes.Equal(cf.Data, data) {
		t.Fatalf("got %+v", cf)
	}
}

func TestAppendStreamRoundTripWithFin(t *testing.T) {
	data := []byte("hello mirage")
	enc := AppendStreamFrame(nil, 4, 0, data, true)
	frames, err := ParseFrames(enc)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	sf := frames[0].(StreamFrame)
	if sf.StreamID != 4 || sf.Offset != 0 || !sf.Fin || !bytes.Equal(sf.Data, data) {
		t.Fatalf("got %+v", sf)
	}
}

func TestParseStreamWithoutLengthBit(t *testing.T) {
	body := []byte{0x09, 0x04, 'h', 'i'}
	frames, err := ParseFrames(body)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	sf := frames[0].(StreamFrame)
	if !sf.Fin || sf.StreamID != 4 || sf.Offset != 0 || string(sf.Data) != "hi" {
		t.Fatalf("got %+v", sf)
	}
}

func TestAppendAckFrameRoundTrip(t *testing.T) {
	enc := AppendAckFrame(nil, 7, 0, 7)
	frames, err := ParseFrames(enc)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	af := frames[0].(AckFrame)
	if af.LargestAcked != 7 || af.FirstAckLen != 7 {
		t.Fatalf("got %+v", af)
	}
}

func TestParseAckECNCountsConsumed(t *testing.T) {
	body := []byte{0x03, 0x05, 0x00, 0x00, 0x05, 0x01, 0x02, 0x03}
	frames, err := ParseFrames(body)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("len=%d want 1", len(frames))
	}
	af := frames[0].(AckFrame)
	if af.LargestAcked != 5 || af.FirstAckLen != 5 {
		t.Fatalf("got %+v", af)
	}
}

func TestParsePaddingCoalesces(t *testing.T) {
	body := []byte{0x00, 0x00, 0x00, 0x01}
	frames, err := ParseFrames(body)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("len=%d want 2", len(frames))
	}
	pf := frames[0].(PaddingFrame)
	if pf.Length != 3 {
		t.Fatalf("padding length=%d want 3", pf.Length)
	}
	if _, ok := frames[1].(PingFrame); !ok {
		t.Fatalf("second %T", frames[1])
	}
}

func TestParseHandshakeDone(t *testing.T) {
	frames, err := ParseFrames([]byte{0x1E})
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	if _, ok := frames[0].(HandshakeDoneFrame); !ok {
		t.Fatalf("type %T", frames[0])
	}
}

func TestParseConnectionCloseTransport(t *testing.T) {
	body := AppendConnectionCloseFrame(nil, 0x100, 0, "bye")
	frames, err := ParseFrames(body)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	cc := frames[0].(ConnectionCloseFrame)
	if cc.IsApp || cc.ErrorCode != 0x100 || string(cc.Reason) != "bye" {
		t.Fatalf("got %+v", cc)
	}
}

func TestParseConnectionCloseApp(t *testing.T) {
	body := []byte{0x1D, 0x40, 0x10, 0x03, 'b', 'y', 'e'}
	frames, err := ParseFrames(body)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	cc := frames[0].(ConnectionCloseFrame)
	if !cc.IsApp || cc.ErrorCode != 0x10 || string(cc.Reason) != "bye" {
		t.Fatalf("got %+v", cc)
	}
}

func TestParseNewConnectionID(t *testing.T) {
	body := []byte{0x18, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD}
	body = append(body, bytes.Repeat([]byte{0xFE}, 16)...)
	frames, err := ParseFrames(body)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	nc := frames[0].(NewConnectionIDFrame)
	if nc.SequenceNumber != 1 || !bytes.Equal(nc.ConnectionID, []byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Fatalf("got %+v", nc)
	}
}

func TestParseNewToken(t *testing.T) {
	body := []byte{0x07, 0x03, 'a', 'b', 'c'}
	frames, err := ParseFrames(body)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	if string(frames[0].(NewTokenFrame).Token) != "abc" {
		t.Fatalf("got %+v", frames[0])
	}
}

func TestParseUnknownFrameType(t *testing.T) {
	if _, err := ParseFrames([]byte{0x40, 0x42}); err == nil {
		t.Fatal("expected unknown frame type error")
	}
}

func TestAppendPaddingFrames(t *testing.T) {
	out := AppendPaddingFrames([]byte{0xFF}, 5)
	want := append([]byte{0xFF}, bytes.Repeat([]byte{0x00}, 5)...)
	if !bytes.Equal(out, want) {
		t.Fatalf("got %x want %x", out, want)
	}
}

func TestAppendPingAndStreamMultiFrame(t *testing.T) {
	enc := AppendPingFrame(nil)
	enc = AppendStreamFrame(enc, 0, 0, []byte("x"), false)
	frames, err := ParseFrames(enc)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("len=%d", len(frames))
	}
	if _, ok := frames[0].(PingFrame); !ok {
		t.Fatalf("first %T", frames[0])
	}
	if frames[1].(StreamFrame).StreamID != 0 {
		t.Fatalf("got %+v", frames[1])
	}
}

func TestParseTruncatedCrypto(t *testing.T) {
	body := []byte{0x06, 0x00, 0x05, 'a', 'b'}
	if _, err := ParseFrames(body); err != ErrFrameTruncated {
		t.Fatalf("want ErrFrameTruncated got %v", err)
	}
}

func TestAppendAckFrameRangesContiguous(t *testing.T) {
	pns := []uint64{5, 4, 3, 2, 1, 0}
	enc := AppendAckFrameRanges(nil, 0, pns)
	frames, err := ParseFrames(enc)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	a, ok := frames[0].(AckFrame)
	if !ok {
		t.Fatalf("type %T", frames[0])
	}
	if a.LargestAcked != 5 || a.FirstAckLen != 5 || len(a.Ranges) != 0 {
		t.Fatalf("got %+v", a)
	}
}

func TestAppendAckFrameRangesGaps(t *testing.T) {
	pns := []uint64{10, 9, 7, 6, 3}
	enc := AppendAckFrameRanges(nil, 0, pns)
	frames, err := ParseFrames(enc)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	a := frames[0].(AckFrame)
	if a.LargestAcked != 10 || a.FirstAckLen != 1 {
		t.Fatalf("first wrong: %+v", a)
	}
	if len(a.Ranges) != 2 {
		t.Fatalf("range count: %d", len(a.Ranges))
	}
	if a.Ranges[0].Gap != 0 || a.Ranges[0].AckLen != 1 {
		t.Fatalf("range 0: %+v", a.Ranges[0])
	}
	if a.Ranges[1].Gap != 1 || a.Ranges[1].AckLen != 0 {
		t.Fatalf("range 1: %+v", a.Ranges[1])
	}
}

func TestAppendAckFrameRangesEmpty(t *testing.T) {
	if got := AppendAckFrameRanges(nil, 0, nil); len(got) != 0 {
		t.Fatalf("want empty, got %d bytes", len(got))
	}
}
