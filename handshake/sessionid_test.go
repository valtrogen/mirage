package handshake

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"testing"

	"github.com/valtrogen/mirage/proto"
)

func mustRead(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		t.Fatalf("rand read: %v", err)
	}
	return b
}

func TestSessionIDRoundTrip(t *testing.T) {
	key := mustRead(t, 16)
	shortID := mustRead(t, proto.SessionIDShortIDLen)
	const wid uint32 = 0x12345678

	dst := make([]byte, proto.SessionIDLen)
	if err := EncodeSessionID(dst, key, shortID, wid); err != nil {
		t.Fatalf("encode: %v", err)
	}

	got, gotWID, err := DecodeSessionID(dst, key)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if gotWID != wid {
		t.Fatalf("windowID: want %x got %x", wid, gotWID)
	}
	if !bytes.Equal(got, shortID) {
		t.Fatalf("short_id mismatch: want %x got %x", shortID, got)
	}
}

func TestSessionIDDeterministicWithFixedNonce(t *testing.T) {
	// Two encodes with the same nonce must produce identical bytes; this
	// is what lets the unit test be reproducible without exposing the
	// nonce on the public API.
	key := mustRead(t, 16)
	shortID := mustRead(t, proto.SessionIDShortIDLen)
	var nonce [proto.SessionIDNonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		t.Fatalf("nonce: %v", err)
	}

	a := make([]byte, proto.SessionIDLen)
	b := make([]byte, proto.SessionIDLen)
	if err := encodeSessionIDWithNonce(a, key, shortID, 1, nonce); err != nil {
		t.Fatalf("encode a: %v", err)
	}
	if err := encodeSessionIDWithNonce(b, key, shortID, 1, nonce); err != nil {
		t.Fatalf("encode b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("encodes diverged with same nonce")
	}
}

func TestSessionIDWindowIDExposedAsAAD(t *testing.T) {
	// Tampering with the WindowID prefix must invalidate the tag.
	key := mustRead(t, 16)
	shortID := mustRead(t, proto.SessionIDShortIDLen)

	dst := make([]byte, proto.SessionIDLen)
	if err := EncodeSessionID(dst, key, shortID, 100); err != nil {
		t.Fatalf("encode: %v", err)
	}
	binary.BigEndian.PutUint32(dst[:4], 101)

	if _, _, err := DecodeSessionID(dst, key); err != ErrInvalidSessionID {
		t.Fatalf("want ErrInvalidSessionID, got %v", err)
	}
}

func TestSessionIDWrongKey(t *testing.T) {
	good := mustRead(t, 16)
	bad := mustRead(t, 16)
	shortID := mustRead(t, proto.SessionIDShortIDLen)

	dst := make([]byte, proto.SessionIDLen)
	if err := EncodeSessionID(dst, good, shortID, 7); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := DecodeSessionID(dst, bad); err != ErrInvalidSessionID {
		t.Fatalf("want ErrInvalidSessionID, got %v", err)
	}
}

func TestSessionIDInvalidLengths(t *testing.T) {
	key := mustRead(t, 16)
	short := mustRead(t, proto.SessionIDShortIDLen)

	if err := EncodeSessionID(make([]byte, 31), key, short, 0); err == nil {
		t.Fatal("encode with short dst: want error")
	}
	if err := EncodeSessionID(make([]byte, proto.SessionIDLen), mustRead(t, 15), short, 0); err == nil {
		t.Fatal("encode with bad key length: want error")
	}
	if err := EncodeSessionID(make([]byte, proto.SessionIDLen), key, mustRead(t, 7), 0); err == nil {
		t.Fatal("encode with bad short_id length: want error")
	}

	if _, _, err := DecodeSessionID(make([]byte, 31), key); err != ErrInvalidSessionID {
		t.Fatalf("decode short src: want ErrInvalidSessionID got %v", err)
	}
}

func TestSessionIDEncodingBytePositions(t *testing.T) {
	// Lock down the field offsets so an accidental refactor does not
	// silently break compatibility with the spec.
	key := mustRead(t, 16)
	shortID := mustRead(t, proto.SessionIDShortIDLen)
	var nonce [proto.SessionIDNonceLen]byte
	for i := range nonce {
		nonce[i] = byte(0xA0 + i)
	}

	dst := make([]byte, proto.SessionIDLen)
	if err := encodeSessionIDWithNonce(dst, key, shortID, 0xDEADBEEF, nonce); err != nil {
		t.Fatalf("encode: %v", err)
	}

	if got := binary.BigEndian.Uint32(dst[:4]); got != 0xDEADBEEF {
		t.Fatalf("window_id at offset 0: got %x", got)
	}
	if !bytes.Equal(dst[12:16], nonce[:]) {
		t.Fatalf("nonce at offset 12: got %x want %x", dst[12:16], nonce[:])
	}
	// ciphertext + tag occupy bytes 4..12 and 16..32 - they must NOT match
	// the plaintext short_id (which would mean encryption silently failed).
	if bytes.Equal(dst[4:12], shortID) {
		t.Fatal("short_id appears in plaintext at offset 4..12")
	}
}

func BenchmarkDecodeSessionID(b *testing.B) {
	key := make([]byte, 16)
	rand.Read(key)
	shortID := make([]byte, proto.SessionIDShortIDLen)
	rand.Read(shortID)
	dst := make([]byte, proto.SessionIDLen)
	if err := EncodeSessionID(dst, key, shortID, 42); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, _, err := DecodeSessionID(dst, key); err != nil {
			b.Fatal(err)
		}
	}
}
