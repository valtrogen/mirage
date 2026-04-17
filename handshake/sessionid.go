package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"github.com/valtrogen/mirage/proto"
)

// ErrInvalidSessionID is returned when the legacy_session_id field is
// malformed or fails AES-GCM verification.
var ErrInvalidSessionID = errors.New("mirage: invalid session_id")

// EncodeSessionID writes the encrypted short-id and authentication tag
// into dst, which must be exactly proto.SessionIDLen bytes long.
//
// windowKey must be 16 bytes (AES-128). shortID must be exactly
// proto.SessionIDShortIDLen bytes. windowID is the low 32 bits of
// floor(unix_time / proto.WindowSeconds).
//
// A fresh per-call nonce is read from crypto/rand.
func EncodeSessionID(dst, windowKey, shortID []byte, windowID uint32) error {
	var nonce [proto.SessionIDNonceLen]byte
	if _, err := io.ReadFull(rand.Reader, nonce[:]); err != nil {
		return err
	}
	return encodeSessionIDWithNonce(dst, windowKey, shortID, windowID, nonce)
}

// encodeSessionIDWithNonce is the deterministic core of EncodeSessionID
// and is used directly by tests that need reproducible output.
func encodeSessionIDWithNonce(dst, windowKey, shortID []byte, windowID uint32, nonce [proto.SessionIDNonceLen]byte) error {
	if len(dst) != proto.SessionIDLen {
		return errors.New("mirage: session_id buffer must be 32 bytes")
	}
	if len(windowKey) != 16 {
		return errors.New("mirage: window key must be 16 bytes")
	}
	if len(shortID) != proto.SessionIDShortIDLen {
		return errors.New("mirage: short_id must be 8 bytes")
	}

	binary.BigEndian.PutUint32(dst[proto.SessionIDWindowOffset:], windowID)
	copy(dst[proto.SessionIDNonceOffset:proto.SessionIDNonceOffset+proto.SessionIDNonceLen], nonce[:])

	var iv [12]byte
	binary.BigEndian.PutUint32(iv[0:4], windowID)
	copy(iv[4:8], nonce[:])

	aead, err := newGCM(windowKey)
	if err != nil {
		return err
	}

	aad := dst[proto.SessionIDWindowOffset : proto.SessionIDWindowOffset+proto.SessionIDWindowLen]
	sealed := aead.Seal(nil, iv[:], shortID, aad)
	if len(sealed) != proto.SessionIDShortIDLen+proto.SessionIDTagLen {
		return errors.New("mirage: AEAD output length mismatch")
	}

	copy(dst[proto.SessionIDShortIDOffset:proto.SessionIDShortIDOffset+proto.SessionIDShortIDLen], sealed[:proto.SessionIDShortIDLen])
	copy(dst[proto.SessionIDTagOffset:proto.SessionIDTagOffset+proto.SessionIDTagLen], sealed[proto.SessionIDShortIDLen:])
	return nil
}

// DecodeSessionID parses src, verifies the AES-GCM tag with windowKey,
// and returns the decrypted short-id together with the WindowID it was
// encrypted under. ErrInvalidSessionID is returned for malformed input
// or tag failure.
//
// The returned short-id slice is freshly allocated; callers may retain it.
func DecodeSessionID(src, windowKey []byte) (shortID []byte, windowID uint32, err error) {
	if len(src) != proto.SessionIDLen {
		return nil, 0, ErrInvalidSessionID
	}
	if len(windowKey) != 16 {
		return nil, 0, errors.New("mirage: window key must be 16 bytes")
	}

	windowID = binary.BigEndian.Uint32(src[proto.SessionIDWindowOffset:])

	var iv [12]byte
	binary.BigEndian.PutUint32(iv[0:4], windowID)
	copy(iv[4:8], src[proto.SessionIDNonceOffset:proto.SessionIDNonceOffset+proto.SessionIDNonceLen])

	aead, err := newGCM(windowKey)
	if err != nil {
		return nil, 0, err
	}

	sealed := make([]byte, 0, proto.SessionIDShortIDLen+proto.SessionIDTagLen)
	sealed = append(sealed, src[proto.SessionIDShortIDOffset:proto.SessionIDShortIDOffset+proto.SessionIDShortIDLen]...)
	sealed = append(sealed, src[proto.SessionIDTagOffset:proto.SessionIDTagOffset+proto.SessionIDTagLen]...)
	aad := src[proto.SessionIDWindowOffset : proto.SessionIDWindowOffset+proto.SessionIDWindowLen]

	plain, err := aead.Open(nil, iv[:], sealed, aad)
	if err != nil {
		return nil, 0, ErrInvalidSessionID
	}
	return plain, windowID, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
