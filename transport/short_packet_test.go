package transport

import (
	"bytes"
	"testing"
)

func TestShortHeaderRoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0x55}, 32)
	pp, err := DerivePacketProtection(CipherSuiteAES128GCMSHA256, secret)
	if err != nil {
		t.Fatalf("DerivePacketProtection: %v", err)
	}
	dcid := bytes.Repeat([]byte{0x77}, 8)

	plain := AppendStreamFrame(nil, 0, 0, []byte("hello stream"), false)
	pkt, err := BuildShortHeader(dcid, 17, plain, false, pp)
	if err != nil {
		t.Fatalf("BuildShortHeader: %v", err)
	}

	parsed, err := ParseShortHeader(pkt, len(dcid), pp)
	if err != nil {
		t.Fatalf("ParseShortHeader: %v", err)
	}
	if parsed.PacketNumber != 17 {
		t.Fatalf("pn = %d", parsed.PacketNumber)
	}
	if parsed.KeyPhase {
		t.Fatal("key phase should be false")
	}

	frames, err := ParseFrames(parsed.Payload)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	sf := frames[0].(StreamFrame)
	if string(sf.Data) != "hello stream" {
		t.Fatalf("data %q", sf.Data)
	}
}

func TestShortHeaderKeyPhaseBit(t *testing.T) {
	secret := bytes.Repeat([]byte{0x66}, 32)
	pp, _ := DerivePacketProtection(CipherSuiteAES128GCMSHA256, secret)
	dcid := bytes.Repeat([]byte{0x88}, 4)
	pkt, _ := BuildShortHeader(dcid, 0, []byte{0x01}, true, pp)
	parsed, err := ParseShortHeader(pkt, len(dcid), pp)
	if err != nil {
		t.Fatalf("ParseShortHeader: %v", err)
	}
	if !parsed.KeyPhase {
		t.Fatal("KeyPhase bit not preserved")
	}
}

func TestShortHeaderRejectsLongHeader(t *testing.T) {
	dcid := bytes.Repeat([]byte{0x99}, 8)
	cpp, _ := DeriveClientInitialProtection(dcid)
	long, _ := BuildLongHeader(LongPacketTypeInitial, QUICv1, dcid, dcid, nil, 0, []byte{0x01}, 1200, cpp)
	if _, err := ParseShortHeader(long, len(dcid), cpp); err != ErrNotShortHeader {
		t.Fatalf("got %v want ErrNotShortHeader", err)
	}
}

func TestShortHeaderRejectsBadAEAD(t *testing.T) {
	secret := bytes.Repeat([]byte{0x77}, 32)
	pp, _ := DerivePacketProtection(CipherSuiteAES128GCMSHA256, secret)
	dcid := bytes.Repeat([]byte{0xAA}, 4)
	pkt, _ := BuildShortHeader(dcid, 0, []byte{0x01}, false, pp)
	pkt[len(pkt)-1] ^= 0xFF
	if _, err := ParseShortHeader(pkt, len(dcid), pp); err != ErrAEADAuthFailed {
		t.Fatalf("got %v want ErrAEADAuthFailed", err)
	}
}
