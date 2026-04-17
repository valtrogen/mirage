package client

import (
	"errors"
	"io"
	"os"
	"testing"
	"time"
)

func TestStreamReadHonoursReadDeadline(t *testing.T) {
	s := newStream(nil, 0)
	if err := s.SetReadDeadline(time.Now().Add(20 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	start := time.Now()
	_, err := s.Read(make([]byte, 16))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read err=%v want DeadlineExceeded", err)
	}
	if d := time.Since(start); d < 15*time.Millisecond || d > 500*time.Millisecond {
		t.Fatalf("Read returned after %v, expected near 20ms", d)
	}
}

func TestStreamReadDeadlineUnblocksSleeper(t *testing.T) {
	s := newStream(nil, 0)
	type result struct {
		n   int
		err error
	}
	done := make(chan result, 1)
	go func() {
		n, err := s.Read(make([]byte, 16))
		done <- result{n, err}
	}()
	time.Sleep(20 * time.Millisecond)
	if err := s.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	select {
	case r := <-done:
		if !errors.Is(r.err, os.ErrDeadlineExceeded) {
			t.Fatalf("Read err=%v want DeadlineExceeded", r.err)
		}
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock after past deadline was set")
	}
}

func TestStreamCancelReadFailsSubsequentReads(t *testing.T) {
	s := newStream(nil, 4)
	if err := s.CancelRead(0x42); err != nil {
		t.Fatalf("CancelRead: %v", err)
	}
	_, err := s.Read(make([]byte, 8))
	var se *StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Read err=%T %v want *StreamError", err, err)
	}
	if !se.Local || se.Code != 0x42 {
		t.Fatalf("StreamError = %+v", se)
	}
}

func TestStreamResetFailsSubsequentWrites(t *testing.T) {
	s := newStream(nil, 4)
	if err := s.Reset(0x99); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	_, err := s.Write([]byte("nope"))
	var se *StreamError
	if !errors.As(err, &se) {
		t.Fatalf("Write err=%T %v want *StreamError", err, err)
	}
	if !se.Local || se.Code != 0x99 {
		t.Fatalf("StreamError = %+v", se)
	}
}

func TestStreamReadAfterFinReturnsEOF(t *testing.T) {
	s := newStream(nil, 0)
	s.deliver(0, []byte("hi"), true)
	buf := make([]byte, 8)
	n, err := s.Read(buf)
	if err != nil || n != 2 || string(buf[:n]) != "hi" {
		t.Fatalf("first Read n=%d err=%v buf=%q", n, err, buf[:n])
	}
	n, err = s.Read(buf)
	if err != io.EOF || n != 0 {
		t.Fatalf("second Read n=%d err=%v want EOF", n, err)
	}
}
