package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/chacha20poly1305"
)

// TLS 1.3 cipher suite identifiers used by QUIC v1 per RFC 9001 §5.3.
const (
	CipherSuiteAES128GCMSHA256        uint16 = 0x1301
	CipherSuiteAES256GCMSHA384        uint16 = 0x1302
	CipherSuiteChaCha20Poly1305SHA256 uint16 = 0x1303
)

// ErrUnsupportedCipherSuite is returned by DerivePacketProtection when
// the TLS-negotiated suite is not one of the three QUIC v1 suites.
var ErrUnsupportedCipherSuite = errors.New("mirage: unsupported QUIC cipher suite")

// PacketProtection groups the AEAD, packet number IV, and header
// protection mask function for one direction of one QUIC encryption
// level. Instances are immutable once derived; callers may share them
// across goroutines provided they synchronise packet number assignment
// upstream.
type PacketProtection struct {
	AEAD       cipher.AEAD
	IV         []byte
	headerMask func(sample []byte) [5]byte
}

// HeaderMask returns the 5-byte XOR mask computed from the AEAD ciphertext
// sample. The mask covers (in order) the four reserved/PN bits of byte
// 0 followed by up to 4 packet-number bytes per RFC 9001 §5.4.
func (pp *PacketProtection) HeaderMask(sample []byte) [5]byte {
	return pp.headerMask(sample)
}

// DerivePacketProtection derives per-direction QUIC packet protection
// from a TLS handshake or application traffic secret. cipherSuiteID is
// one of the three RFC 9001 §5.3 identifiers; secret is the raw TLS
// secret from the QUICSetReadSecret/QUICSetWriteSecret event.
func DerivePacketProtection(cipherSuiteID uint16, secret []byte) (*PacketProtection, error) {
	switch cipherSuiteID {
	case CipherSuiteAES128GCMSHA256:
		return derivePPAESGCM(sha256.New, 16, secret)
	case CipherSuiteAES256GCMSHA384:
		return derivePPAESGCM(sha512.New384, 32, secret)
	case CipherSuiteChaCha20Poly1305SHA256:
		return derivePPChaChaPoly(secret)
	default:
		return nil, ErrUnsupportedCipherSuite
	}
}

func derivePPAESGCM(h func() hash.Hash, keyLen int, secret []byte) (*PacketProtection, error) {
	key, err := hkdfExpandLabelHash(h, secret, "quic key", keyLen)
	if err != nil {
		return nil, err
	}
	iv, err := hkdfExpandLabelHash(h, secret, "quic iv", 12)
	if err != nil {
		return nil, err
	}
	hp, err := hkdfExpandLabelHash(h, secret, "quic hp", keyLen)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	hpBlock, err := aes.NewCipher(hp)
	if err != nil {
		return nil, err
	}
	return &PacketProtection{
		AEAD: aead,
		IV:   iv,
		headerMask: func(sample []byte) [5]byte {
			var mask [5]byte
			var enc [16]byte
			hpBlock.Encrypt(enc[:], sample[:16])
			copy(mask[:], enc[:5])
			return mask
		},
	}, nil
}

func derivePPChaChaPoly(secret []byte) (*PacketProtection, error) {
	key, err := hkdfExpandLabelHash(sha256.New, secret, "quic key", 32)
	if err != nil {
		return nil, err
	}
	iv, err := hkdfExpandLabelHash(sha256.New, secret, "quic iv", 12)
	if err != nil {
		return nil, err
	}
	hp, err := hkdfExpandLabelHash(sha256.New, secret, "quic hp", 32)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &PacketProtection{
		AEAD: aead,
		IV:   iv,
		headerMask: func(sample []byte) [5]byte {
			counter := binary.LittleEndian.Uint32(sample[:4])
			nonce := sample[4:16]
			c, err := chacha20.NewUnauthenticatedCipher(hp, nonce)
			if err != nil {
				return [5]byte{}
			}
			c.SetCounter(counter)
			var mask [5]byte
			c.XORKeyStream(mask[:], mask[:])
			return mask
		},
	}, nil
}

// NextAppSecret derives the application-level traffic secret for the
// next key phase (RFC 9001 §6.1):
//
//	next_secret = HKDF-Expand-Label(secret, "quic ku", "", Hash.length)
//
// cipherSuiteID picks the hash and output length: SHA-256 (32) for
// AES-128-GCM and ChaCha20-Poly1305, SHA-384 (48) for AES-256-GCM.
func NextAppSecret(cipherSuiteID uint16, secret []byte) ([]byte, error) {
	switch cipherSuiteID {
	case CipherSuiteAES128GCMSHA256, CipherSuiteChaCha20Poly1305SHA256:
		return hkdfExpandLabelHash(sha256.New, secret, "quic ku", 32)
	case CipherSuiteAES256GCMSHA384:
		return hkdfExpandLabelHash(sha512.New384, secret, "quic ku", 48)
	default:
		return nil, ErrUnsupportedCipherSuite
	}
}

// RekeyForUpdate derives a new PacketProtection for the next key
// phase. The AEAD key and IV are recomputed from nextSecret; the
// header protection function is shared with base because RFC 9001 §6
// keeps the header protection key constant across key updates.
func RekeyForUpdate(cipherSuiteID uint16, base *PacketProtection, nextSecret []byte) (*PacketProtection, error) {
	if base == nil {
		return nil, errors.New("mirage: nil base protection")
	}
	switch cipherSuiteID {
	case CipherSuiteAES128GCMSHA256:
		return rekeyAESGCM(sha256.New, 16, base, nextSecret)
	case CipherSuiteAES256GCMSHA384:
		return rekeyAESGCM(sha512.New384, 32, base, nextSecret)
	case CipherSuiteChaCha20Poly1305SHA256:
		return rekeyChaChaPoly(base, nextSecret)
	default:
		return nil, ErrUnsupportedCipherSuite
	}
}

func rekeyAESGCM(h func() hash.Hash, keyLen int, base *PacketProtection, secret []byte) (*PacketProtection, error) {
	key, err := hkdfExpandLabelHash(h, secret, "quic key", keyLen)
	if err != nil {
		return nil, err
	}
	iv, err := hkdfExpandLabelHash(h, secret, "quic iv", 12)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &PacketProtection{
		AEAD:       aead,
		IV:         iv,
		headerMask: base.headerMask,
	}, nil
}

func rekeyChaChaPoly(base *PacketProtection, secret []byte) (*PacketProtection, error) {
	key, err := hkdfExpandLabelHash(sha256.New, secret, "quic key", 32)
	if err != nil {
		return nil, err
	}
	iv, err := hkdfExpandLabelHash(sha256.New, secret, "quic iv", 12)
	if err != nil {
		return nil, err
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, err
	}
	return &PacketProtection{
		AEAD:       aead,
		IV:         iv,
		headerMask: base.headerMask,
	}, nil
}

// hkdfExpandLabelHash implements HKDF-Expand-Label (TLS 1.3 §7.1) with a
// caller-supplied hash function. The original quic_keys.go retains
// hkdfExpandLabel as a SHA-256 shim used by the Initial code path.
func hkdfExpandLabelHash(h func() hash.Hash, secret []byte, label string, length int) ([]byte, error) {
	const labelPrefix = "tls13 "
	full := labelPrefix + label

	info := make([]byte, 0, 2+1+len(full)+1)
	info = append(info, byte(length>>8), byte(length))
	info = append(info, byte(len(full)))
	info = append(info, full...)
	info = append(info, 0)

	return hkdf.Expand(h, secret, string(info), length)
}
