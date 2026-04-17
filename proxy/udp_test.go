package proxy

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestUDPFrameRoundtripIPv4(t *testing.T) {
	want := UDPFrame{
		Host:    "192.0.2.7",
		Port:    443,
		Payload: []byte("hello"),
	}
	buf, err := AppendUDPFrame(nil, want)
	if err != nil {
		t.Fatalf("AppendUDPFrame: %v", err)
	}
	got, err := ReadUDPFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadUDPFrame: %v", err)
	}
	if got.Host != want.Host || got.Port != want.Port {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("payload mismatch: %q vs %q", got.Payload, want.Payload)
	}
}

func TestUDPFrameRoundtripIPv6(t *testing.T) {
	want := UDPFrame{
		Host:    "2001:db8::1",
		Port:    8443,
		Payload: bytes.Repeat([]byte{0xAB}, 1500),
	}
	buf, err := AppendUDPFrame(nil, want)
	if err != nil {
		t.Fatalf("AppendUDPFrame: %v", err)
	}
	got, err := ReadUDPFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadUDPFrame: %v", err)
	}
	if got.Host != want.Host || got.Port != want.Port || !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("roundtrip mismatch: %+v", got)
	}
}

func TestUDPFrameRoundtripDomain(t *testing.T) {
	want := UDPFrame{
		Host:    "example.test",
		Port:    53,
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	buf, err := AppendUDPFrame(nil, want)
	if err != nil {
		t.Fatalf("AppendUDPFrame: %v", err)
	}
	got, err := ReadUDPFrame(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadUDPFrame: %v", err)
	}
	if got.Host != want.Host || got.Port != want.Port {
		t.Fatalf("got %+v want %+v", got, want)
	}
	if !bytes.Equal(got.Payload, want.Payload) {
		t.Fatalf("payload mismatch")
	}
}

func TestUDPFrameTruncatedReturnsProtocolError(t *testing.T) {
	complete, err := AppendUDPFrame(nil, UDPFrame{Host: "10.0.0.1", Port: 1, Payload: []byte("xy")})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	for i := 1; i < len(complete); i++ {
		_, err := ReadUDPFrame(bytes.NewReader(complete[:i]))
		if err == nil {
			t.Fatalf("expected error at truncation %d", i)
		}
	}
}

func TestUDPFrameRejectsUnknownAddrType(t *testing.T) {
	// total = 1(atyp) + 4(addr) + 2(port) + 0(payload) = 7
	bad := []byte{0x00, 0x07, 0xFF, 0, 0, 0, 0, 0, 0}
	_, err := ReadUDPFrame(bytes.NewReader(bad))
	if err == nil || !errors.Is(err, ErrProtocol) {
		t.Fatalf("expected ErrProtocol, got %v", err)
	}
	if !strings.Contains(err.Error(), "atyp") {
		t.Fatalf("error should mention atyp: %v", err)
	}
}

func TestUDPFrameRejectsOversizePayload(t *testing.T) {
	tooBig := UDPFrame{Host: "10.0.0.1", Port: 1, Payload: make([]byte, MaxUDPFrameBody+1)}
	if _, err := AppendUDPFrame(nil, tooBig); !errors.Is(err, ErrUDPFrameTooLarge) {
		t.Fatalf("expected ErrUDPFrameTooLarge, got %v", err)
	}
}
