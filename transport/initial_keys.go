package transport

import (
	"crypto/hkdf"
	"crypto/sha256"
)

// initialSalt is the QUIC v1 Initial salt from RFC 9001 §5.2.
var initialSalt = []byte{
	0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
	0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
	0xcc, 0xbb, 0x7f, 0x0a,
}

// initialSecrets bundles the Initial-level AES-128-GCM AEAD material
// for the client direction. The dispatcher only ever needs to read
// (decrypt) Initial packets sent by the client, so we don't compute
// the server-direction secrets.
type initialSecrets struct {
	clientKey [16]byte
	clientIV  [12]byte
	clientHP  [16]byte
}

// deriveInitialSecrets implements the Initial-secret derivation from
// RFC 9001 §5.2 for the client direction. dcid is the destination
// connection ID carried in the client's first Initial packet.
func deriveInitialSecrets(dcid []byte) (*initialSecrets, error) {
	initial, err := hkdf.Extract(sha256.New, dcid, initialSalt)
	if err != nil {
		return nil, err
	}
	clientSecret, err := hkdfExpandLabelSHA256(initial, "client in", 32)
	if err != nil {
		return nil, err
	}
	key, err := hkdfExpandLabelSHA256(clientSecret, "quic key", 16)
	if err != nil {
		return nil, err
	}
	iv, err := hkdfExpandLabelSHA256(clientSecret, "quic iv", 12)
	if err != nil {
		return nil, err
	}
	hp, err := hkdfExpandLabelSHA256(clientSecret, "quic hp", 16)
	if err != nil {
		return nil, err
	}
	out := &initialSecrets{}
	copy(out.clientKey[:], key)
	copy(out.clientIV[:], iv)
	copy(out.clientHP[:], hp)
	return out, nil
}

// hkdfExpandLabelSHA256 is HKDF-Expand-Label (TLS 1.3 §7.1) hard-wired
// to SHA-256, which is what RFC 9001 mandates for Initial-secret
// derivation regardless of the cipher suite eventually negotiated.
func hkdfExpandLabelSHA256(secret []byte, label string, length int) ([]byte, error) {
	const labelPrefix = "tls13 "
	full := labelPrefix + label

	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)

	return hkdf.Expand(sha256.New, secret, string(info), length)
}
