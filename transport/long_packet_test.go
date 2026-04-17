package transport

import (
	"bytes"
	"testing"
)

func TestBuildLongHeaderInitialRoundTrip(t *testing.T) {
	dcid := bytes.Repeat([]byte{0xC1}, 8)
	scid := bytes.Repeat([]byte{0xC2}, 8)
	pp, err := DeriveClientInitialProtection(dcid)
	if err != nil {
		t.Fatalf("DeriveClientInitialProtection: %v", err)
	}

	plain := AppendCryptoFrame(nil, 0, []byte("hello tls"))
	pkt, err := BuildLongHeader(LongPacketTypeInitial, QUICv1, dcid, scid, nil, 1, plain, 1200, pp)
	if err != nil {
		t.Fatalf("BuildLongHeader: %v", err)
	}
	if len(pkt) < 1200 {
		t.Fatalf("packet length %d below 1200 padding floor", len(pkt))
	}

	parsed, err := ParseLongHeader(pkt, pp)
	if err != nil {
		t.Fatalf("ParseLongHeader: %v", err)
	}
	if parsed.Type != LongPacketTypeInitial {
		t.Fatalf("type = %d", parsed.Type)
	}
	if parsed.PacketNumber != 1 {
		t.Fatalf("pn = %d", parsed.PacketNumber)
	}
	if !bytes.Equal(parsed.DCID, dcid) {
		t.Fatalf("dcid mismatch")
	}

	frames, err := ParseFrames(parsed.Payload)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	var foundCrypto bool
	for _, f := range frames {
		if cf, ok := f.(CryptoFrame); ok {
			if string(cf.Data) != "hello tls" {
				t.Fatalf("crypto data %q", cf.Data)
			}
			foundCrypto = true
		}
	}
	if !foundCrypto {
		t.Fatal("CRYPTO frame not present after round trip")
	}
}

func TestBuildLongHeaderHandshakeRoundTrip(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, 32)
	pp, err := DerivePacketProtection(CipherSuiteAES128GCMSHA256, secret)
	if err != nil {
		t.Fatalf("DerivePacketProtection: %v", err)
	}
	dcid := bytes.Repeat([]byte{0x10}, 4)
	scid := bytes.Repeat([]byte{0x20}, 4)
	plain := AppendCryptoFrame(nil, 0, []byte("client finished"))
	plain = AppendAckFrame(plain, 0, 0, 0)

	pkt, err := BuildLongHeader(LongPacketTypeHandshake, QUICv1, dcid, scid, nil, 0, plain, 0, pp)
	if err != nil {
		t.Fatalf("BuildLongHeader: %v", err)
	}

	parsed, err := ParseLongHeader(pkt, pp)
	if err != nil {
		t.Fatalf("ParseLongHeader: %v", err)
	}
	if parsed.Type != LongPacketTypeHandshake {
		t.Fatalf("type = %d", parsed.Type)
	}
	if parsed.PacketNumber != 0 {
		t.Fatalf("pn = %d", parsed.PacketNumber)
	}
	if len(parsed.Token) != 0 {
		t.Fatalf("handshake should have no token, got %x", parsed.Token)
	}

	frames, err := ParseFrames(parsed.Payload)
	if err != nil {
		t.Fatalf("ParseFrames: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("frame count %d", len(frames))
	}
}

func TestBuildLongHeaderRejectsTokenOnHandshake(t *testing.T) {
	secret := bytes.Repeat([]byte{0xCD}, 32)
	pp, _ := DerivePacketProtection(CipherSuiteAES128GCMSHA256, secret)
	if _, err := BuildLongHeader(LongPacketTypeHandshake, QUICv1, []byte{1}, []byte{2}, []byte{0xFF}, 0, []byte{0x01}, 0, pp); err == nil {
		t.Fatal("expected error for token on Handshake")
	}
}

func TestParseLongHeaderRejectsBadAEAD(t *testing.T) {
	dcid := bytes.Repeat([]byte{0x11}, 8)
	scid := bytes.Repeat([]byte{0x22}, 8)
	pp, _ := DeriveClientInitialProtection(dcid)
	plain := AppendCryptoFrame(nil, 0, []byte("x"))
	pkt, _ := BuildLongHeader(LongPacketTypeInitial, QUICv1, dcid, scid, nil, 0, plain, 1200, pp)
	pkt[len(pkt)-1] ^= 0xFF
	if _, err := ParseLongHeader(pkt, pp); err != ErrAEADAuthFailed {
		t.Fatalf("got %v want ErrAEADAuthFailed", err)
	}
}

func TestServerInitialDirectionDistinct(t *testing.T) {
	dcid := bytes.Repeat([]byte{0x33}, 8)
	cpp, _ := DeriveClientInitialProtection(dcid)
	spp, _ := DeriveServerInitialProtection(dcid)
	if bytes.Equal(cpp.IV, spp.IV) {
		t.Fatal("client and server Initial IVs must differ")
	}
}
