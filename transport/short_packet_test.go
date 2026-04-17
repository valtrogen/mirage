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

func TestShortHeaderKeyUpdateUsesNextPP(t *testing.T) {
	secret := bytes.Repeat([]byte{0x99}, 32)
	current, err := DerivePacketProtection(CipherSuiteAES128GCMSHA256, secret)
	if err != nil {
		t.Fatalf("DerivePacketProtection: %v", err)
	}
	nextSecret, err := NextAppSecret(CipherSuiteAES128GCMSHA256, secret)
	if err != nil {
		t.Fatalf("NextAppSecret: %v", err)
	}
	next, err := RekeyForUpdate(CipherSuiteAES128GCMSHA256, current, nextSecret)
	if err != nil {
		t.Fatalf("RekeyForUpdate: %v", err)
	}
	dcid := bytes.Repeat([]byte{0xCC}, 8)

	// Sender flips key phase and uses the rotated AEAD.
	pkt, err := BuildShortHeader(dcid, 42, []byte{0x01}, true, next)
	if err != nil {
		t.Fatalf("BuildShortHeader: %v", err)
	}
	parsed, used, err := ParseShortHeaderWithUpdate(pkt, len(dcid), current, next, false)
	if err != nil {
		t.Fatalf("ParseShortHeaderWithUpdate: %v", err)
	}
	if !used {
		t.Fatal("usedNext should be true after key phase flip")
	}
	if !parsed.KeyPhase {
		t.Fatal("parsed.KeyPhase should reflect the flipped bit")
	}
	if parsed.PacketNumber != 42 {
		t.Fatalf("pn = %d", parsed.PacketNumber)
	}
}

func TestShortHeaderKeyUpdateRequiresNextPP(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAA}, 32)
	current, _ := DerivePacketProtection(CipherSuiteAES128GCMSHA256, secret)
	nextSecret, _ := NextAppSecret(CipherSuiteAES128GCMSHA256, secret)
	next, _ := RekeyForUpdate(CipherSuiteAES128GCMSHA256, current, nextSecret)
	dcid := bytes.Repeat([]byte{0xBB}, 8)
	pkt, _ := BuildShortHeader(dcid, 1, []byte{0x01}, true, next)
	if _, _, err := ParseShortHeaderWithUpdate(pkt, len(dcid), current, nil, false); err != ErrAEADAuthFailed {
		t.Fatalf("got %v want ErrAEADAuthFailed without next pp", err)
	}
}

func TestShortHeaderKeyUpdateNoFlipUsesCurrent(t *testing.T) {
	secret := bytes.Repeat([]byte{0xDD}, 32)
	current, _ := DerivePacketProtection(CipherSuiteAES128GCMSHA256, secret)
	nextSecret, _ := NextAppSecret(CipherSuiteAES128GCMSHA256, secret)
	next, _ := RekeyForUpdate(CipherSuiteAES128GCMSHA256, current, nextSecret)
	dcid := bytes.Repeat([]byte{0xEE}, 8)
	pkt, _ := BuildShortHeader(dcid, 7, []byte{0x01}, false, current)
	parsed, used, err := ParseShortHeaderWithUpdate(pkt, len(dcid), current, next, false)
	if err != nil {
		t.Fatalf("ParseShortHeaderWithUpdate: %v", err)
	}
	if used {
		t.Fatal("usedNext should be false when key phase matches")
	}
	if parsed.PacketNumber != 7 {
		t.Fatalf("pn = %d", parsed.PacketNumber)
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
