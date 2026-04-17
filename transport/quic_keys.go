package transport

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// QUIC v1 Initial salt (RFC 9001 §5.2).
var quicV1InitialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// initialSecrets holds the keying material derived from the client-chosen
// connection ID for the Initial packet number space.
type initialSecrets struct {
	clientKey [16]byte
	clientIV  [12]byte
	clientHP  [16]byte
}

// deriveInitialSecrets derives the client-side Initial AEAD and header
// protection material from dcid per RFC 9001 §5.2.
func deriveInitialSecrets(dcid []byte) (initialSecrets, error) {
	prk, err := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	if err != nil {
		return initialSecrets{}, err
	}
	clientInitial, err := hkdfExpandLabel(prk, "client in", 32)
	if err != nil {
		return initialSecrets{}, err
	}
	out := initialSecrets{}

	key, err := hkdfExpandLabel(clientInitial, "quic key", 16)
	if err != nil {
		return initialSecrets{}, err
	}
	copy(out.clientKey[:], key)

	iv, err := hkdfExpandLabel(clientInitial, "quic iv", 12)
	if err != nil {
		return initialSecrets{}, err
	}
	copy(out.clientIV[:], iv)

	hp, err := hkdfExpandLabel(clientInitial, "quic hp", 16)
	if err != nil {
		return initialSecrets{}, err
	}
	copy(out.clientHP[:], hp)

	return out, nil
}

// hkdfExpandLabel implements HKDF-Expand-Label as defined in TLS 1.3
// (RFC 8446 §7.1) with an empty Context. It returns length bytes.
func hkdfExpandLabel(secret []byte, label string, length int) ([]byte, error) {
	const labelPrefix = "tls13 "
	full := labelPrefix + label

	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)

	return hkdf.Expand(sha256.New, secret, string(info), length)
}
