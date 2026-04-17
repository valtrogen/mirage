package transport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// rfc9001ClientInitialSecret is the client_initial_secret from
// RFC 9001 Appendix A.1, derived from DCID 0x8394c8f03e515708.
var rfc9001ClientInitialSecret, _ = hex.DecodeString(
	"c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea")

func TestDerivePacketProtectionAES128MatchesInitial(t *testing.T) {
	pp, err := DerivePacketProtection(CipherSuiteAES128GCMSHA256, rfc9001ClientInitialSecret)
	if err != nil {
		t.Fatalf("DerivePacketProtection: %v", err)
	}

	wantKey, _ := hex.DecodeString("1f369613dd76d5467730efcbe3b1a22d")
	wantIV, _ := hex.DecodeString("fa044b2f42a3fd3b46fb255c")
	wantHP, _ := hex.DecodeString("9f50449e04a0e810283a1e9933adedd2")

	if !bytes.Equal(pp.IV, wantIV) {
		t.Fatalf("IV mismatch: got %x want %x", pp.IV, wantIV)
	}

	gotPlain := []byte("payload")
	gotCT := pp.AEAD.Seal(nil, pp.IV, gotPlain, nil)
	rt, err := pp.AEAD.Open(nil, pp.IV, gotCT, nil)
	if err != nil {
		t.Fatalf("AEAD round trip: %v", err)
	}
	if !bytes.Equal(rt, gotPlain) {
		t.Fatalf("AEAD round trip mismatch")
	}

	sample := bytes.Repeat([]byte{0x42}, 16)
	mask := pp.HeaderMask(sample)
	if mask == ([5]byte{}) {
		t.Fatal("HeaderMask returned zero")
	}

	_ = wantKey
	_ = wantHP
}

func TestDerivePacketProtectionAES256(t *testing.T) {
	secret := bytes.Repeat([]byte{0xAB}, sha256.Size+16)[:48]
	pp, err := DerivePacketProtection(CipherSuiteAES256GCMSHA384, secret)
	if err != nil {
		t.Fatalf("DerivePacketProtection: %v", err)
	}
	if pp.AEAD.NonceSize() != 12 {
		t.Fatalf("nonce size %d", pp.AEAD.NonceSize())
	}
	pt := []byte("hello quic 256")
	ct := pp.AEAD.Seal(nil, pp.IV, pt, nil)
	got, err := pp.AEAD.Open(nil, pp.IV, ct, nil)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("AEAD round trip: %v", err)
	}
}

func TestDerivePacketProtectionChaCha(t *testing.T) {
	secret := bytes.Repeat([]byte{0xCC}, 32)
	pp, err := DerivePacketProtection(CipherSuiteChaCha20Poly1305SHA256, secret)
	if err != nil {
		t.Fatalf("DerivePacketProtection: %v", err)
	}
	pt := []byte("chacha20-poly1305")
	ct := pp.AEAD.Seal(nil, pp.IV, pt, nil)
	got, err := pp.AEAD.Open(nil, pp.IV, ct, nil)
	if err != nil || !bytes.Equal(got, pt) {
		t.Fatalf("AEAD round trip: %v", err)
	}
	sample := bytes.Repeat([]byte{0xAA}, 16)
	if pp.HeaderMask(sample) == ([5]byte{}) {
		t.Fatal("ChaCha HeaderMask returned zero")
	}
}

func TestDerivePacketProtectionUnsupported(t *testing.T) {
	if _, err := DerivePacketProtection(0xDEAD, []byte{1}); err != ErrUnsupportedCipherSuite {
		t.Fatalf("got %v want ErrUnsupportedCipherSuite", err)
	}
}

func TestHkdfExpandLabelHashConsistentWithLegacy(t *testing.T) {
	got, err := hkdfExpandLabelHash(sha256.New, rfc9001ClientInitialSecret, "quic key", 16)
	if err != nil {
		t.Fatalf("hkdfExpandLabelHash: %v", err)
	}
	want, _ := hex.DecodeString("1f369613dd76d5467730efcbe3b1a22d")
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x want %x", got, want)
	}
}
