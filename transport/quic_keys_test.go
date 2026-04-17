package transport

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Test vectors are from RFC 9001 Appendix A.1.
const (
	rfcDCIDHex      = "8394c8f03e515708"
	rfcClientKeyHex = "1f369613dd76d5467730efcbe3b1a22d"
	rfcClientIVHex  = "fa044b2f42a3fd3b46fb255c"
	rfcClientHPHex  = "9f50449e04a0e810283a1e9933adedd2"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func TestDeriveInitialSecretsRFCVectors(t *testing.T) {
	dcid := mustHex(t, rfcDCIDHex)
	got, err := deriveInitialSecrets(dcid)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}

	if !bytes.Equal(got.clientKey[:], mustHex(t, rfcClientKeyHex)) {
		t.Fatalf("client key: got %x want %s", got.clientKey, rfcClientKeyHex)
	}
	if !bytes.Equal(got.clientIV[:], mustHex(t, rfcClientIVHex)) {
		t.Fatalf("client iv: got %x want %s", got.clientIV, rfcClientIVHex)
	}
	if !bytes.Equal(got.clientHP[:], mustHex(t, rfcClientHPHex)) {
		t.Fatalf("client hp: got %x want %s", got.clientHP, rfcClientHPHex)
	}
}
