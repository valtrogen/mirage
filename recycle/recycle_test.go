package recycle

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/valtrogen/mirage/proto"
)

func TestBoundsSampleInRange(t *testing.T) {
	b := DefaultBounds()
	for i := 0; i < 256; i++ {
		th, err := b.Sample(rand.Reader)
		if err != nil {
			t.Fatalf("Sample: %v", err)
		}
		if th.Age < b.AgeMin || th.Age > b.AgeMax {
			t.Fatalf("age %v out of [%v,%v]", th.Age, b.AgeMin, b.AgeMax)
		}
		if th.Bytes < b.BytesMin || th.Bytes > b.BytesMax {
			t.Fatalf("bytes %d out of [%d,%d]", th.Bytes, b.BytesMin, b.BytesMax)
		}
	}
}

func TestBoundsSampleEqualMinMax(t *testing.T) {
	b := Bounds{AgeMin: time.Second, AgeMax: time.Second, BytesMin: 100, BytesMax: 100}
	th, err := b.Sample(rand.Reader)
	if err != nil {
		t.Fatalf("Sample: %v", err)
	}
	if th.Age != time.Second || th.Bytes != 100 {
		t.Fatalf("got %+v", th)
	}
}

func TestBoundsSampleInvalid(t *testing.T) {
	b := Bounds{AgeMin: 2 * time.Second, AgeMax: time.Second}
	if _, err := b.Sample(rand.Reader); !errors.Is(err, ErrInvalidBounds) {
		t.Fatalf("want ErrInvalidBounds got %v", err)
	}
}

func TestTrackerReachedByBytes(t *testing.T) {
	tr := NewTracker(Threshold{Age: time.Hour, Bytes: 1000})
	if tr.Reached() {
		t.Fatal("fresh tracker should not be reached")
	}
	tr.AddBytes(500)
	if tr.Reached() {
		t.Fatal("500 < 1000")
	}
	tr.AddBytes(500)
	if !tr.Reached() {
		t.Fatal("1000 should trip threshold")
	}
}

func TestTrackerReachedByAge(t *testing.T) {
	tr := NewTracker(Threshold{Age: 10 * time.Millisecond, Bytes: 1 << 30})
	if tr.Reached() {
		t.Fatal("fresh")
	}
	time.Sleep(15 * time.Millisecond)
	if !tr.Reached() {
		t.Fatal("age threshold should have tripped")
	}
}

func TestHintRoundTrip(t *testing.T) {
	for _, want := range []time.Duration{0, time.Millisecond, 30 * time.Second, 65*time.Second + 535*time.Millisecond} {
		body := EncodeHint(Hint{HandoffWindow: want})
		if len(body) != 2 {
			t.Fatalf("body len %d", len(body))
		}
		got, err := DecodeHint(body)
		if err != nil {
			t.Fatalf("DecodeHint: %v", err)
		}
		if got.HandoffWindow != want {
			t.Fatalf("got %v want %v", got.HandoffWindow, want)
		}
	}
}

func TestHintEncodeClampsLargeAndNegative(t *testing.T) {
	body := EncodeHint(Hint{HandoffWindow: 10 * time.Hour})
	got, err := DecodeHint(body)
	if err != nil {
		t.Fatalf("DecodeHint: %v", err)
	}
	if got.HandoffWindow != 65535*time.Millisecond {
		t.Fatalf("not clamped: %v", got.HandoffWindow)
	}
	body = EncodeHint(Hint{HandoffWindow: -time.Second})
	got, err = DecodeHint(body)
	if err != nil {
		t.Fatalf("DecodeHint: %v", err)
	}
	if got.HandoffWindow != 0 {
		t.Fatalf("negative not clamped: %v", got.HandoffWindow)
	}
}

func TestDecodeHintBodyLen(t *testing.T) {
	if _, err := DecodeHint([]byte{0x01}); !errors.Is(err, ErrHintBodyLen) {
		t.Fatalf("want ErrHintBodyLen got %v", err)
	}
}

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	body := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	if err := WriteFrame(&buf, proto.FrameTypeKeepalivePadding, body); err != nil {
		t.Fatal(err)
	}
	gotType, gotBody, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if gotType != proto.FrameTypeKeepalivePadding {
		t.Fatalf("type %v", gotType)
	}
	if !bytes.Equal(gotBody, body) {
		t.Fatalf("body %x want %x", gotBody, body)
	}
}

func TestFrameEmptyBody(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteFrame(&buf, proto.FrameType(0x42), nil); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != proto.FrameHeaderLen {
		t.Fatalf("header-only frame should be %d bytes, got %d", proto.FrameHeaderLen, buf.Len())
	}
	gotType, gotBody, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if gotType != proto.FrameType(0x42) || gotBody != nil {
		t.Fatalf("got type=%v body=%x", gotType, gotBody)
	}
}

func TestFrameTooLarge(t *testing.T) {
	body := make([]byte, proto.MaxFrameBodyLen+1)
	if err := WriteFrame(io.Discard, proto.FrameType(1), body); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("want ErrFrameTooLarge got %v", err)
	}
}

func TestWriteHintEndToEnd(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHint(&buf, Hint{HandoffWindow: DefaultHandoffWindow}); err != nil {
		t.Fatal(err)
	}
	gotType, gotBody, err := ReadFrame(&buf)
	if err != nil {
		t.Fatal(err)
	}
	if gotType != proto.FrameTypeConnectionRecycleHint {
		t.Fatalf("type %v", gotType)
	}
	hint, err := DecodeHint(gotBody)
	if err != nil {
		t.Fatal(err)
	}
	if hint.HandoffWindow != DefaultHandoffWindow {
		t.Fatalf("got %v", hint.HandoffWindow)
	}
}
