package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// BuildInitial constructs a QUIC v1 Initial packet that ParseInitial can
// decode. It is intended for tests and tools; production clients should
// use a real QUIC implementation.
//
// dcid must be 8..20 bytes. scid may be empty. plaintext is the raw
// frames body (typically a CRYPTO frame containing a TLS ClientHello,
// optionally followed by PADDING). The returned datagram is exactly
// padToLen bytes long; padToLen must be at least header+5+plaintext+16.
func BuildInitial(dcid, scid []byte, packetNumber uint32, plaintext []byte, padToLen int) ([]byte, error) {
	if len(dcid) < 8 || len(dcid) > MaxConnectionIDLen {
		return nil, errors.New("mirage: dcid must be 8..20 bytes")
	}
	if len(scid) > MaxConnectionIDLen {
		return nil, errors.New("mirage: scid too long")
	}

	// Fixed 4-byte packet number for simplicity.
	const pnLen = 4
	const tagLen = 16

	headerWithoutLength := 1 + 4 + 1 + len(dcid) + 1 + len(scid) + 1
	// payload = pn + plaintext + tag
	// We may need to pad plaintext if padToLen > minimum.
	overhead := headerWithoutLength + 2 + pnLen + tagLen
	if padToLen < overhead+len(plaintext) {
		return nil, errors.New("mirage: padToLen too small for plaintext")
	}
	frames := make([]byte, padToLen-overhead)
	copy(frames, plaintext)
	// frames[len(plaintext):] stays zero, which is the QUIC PADDING frame.

	payloadLen := pnLen + len(frames) + tagLen
	if VarIntLen(uint64(payloadLen)) != 2 {
		return nil, errors.New("mirage: payload length does not fit a 2-byte varint; pick padToLen accordingly")
	}

	out := make([]byte, padToLen)
	off := 0
	out[off] = 0xC0 | byte(pnLen-1)
	off++
	binary.BigEndian.PutUint32(out[off:], QUICv1)
	off += 4
	out[off] = byte(len(dcid))
	off++
	copy(out[off:], dcid)
	off += len(dcid)
	out[off] = byte(len(scid))
	off++
	copy(out[off:], scid)
	off += len(scid)
	out[off] = 0x00
	off++
	// 2-byte payload length varint: prefix 01 in top bits.
	out[off] = 0x40 | byte(payloadLen>>8)
	out[off+1] = byte(payloadLen)
	off += 2
	pnOffset := off
	binary.BigEndian.PutUint32(out[off:], packetNumber)
	off += pnLen

	secrets, err := deriveInitialSecrets(dcid)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(secrets.clientKey[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	var iv [12]byte
	copy(iv[:], secrets.clientIV[:])
	for i := 0; i < 4; i++ {
		iv[12-1-i] ^= byte(packetNumber >> (8 * i))
	}

	aad := make([]byte, pnOffset+pnLen)
	copy(aad, out[:pnOffset+pnLen])

	ciphertext := aead.Seal(nil, iv[:], frames, aad)
	if len(ciphertext) != len(frames)+tagLen {
		return nil, errors.New("mirage: AEAD output length mismatch")
	}
	copy(out[pnOffset+pnLen:], ciphertext)

	// Apply header protection.
	sample := out[pnOffset+4 : pnOffset+4+16]
	mask, err := computeHeaderMask(secrets.clientHP[:], sample)
	if err != nil {
		return nil, err
	}
	out[0] ^= mask[0] & 0x0F
	for i := 0; i < pnLen; i++ {
		out[pnOffset+i] ^= mask[1+i]
	}
	return out, nil
}

// BuildClientHelloHandshake assembles a minimal TLS 1.3 ClientHello
// Handshake record carrying sessionID. Only the fields mirage inspects
// are populated; the message will not parse as a real ClientHello but is
// sufficient for ExtractClientHelloSessionID.
func BuildClientHelloHandshake(sessionID []byte) []byte {
	if len(sessionID) > 32 {
		panic("mirage: session_id > 32 bytes")
	}
	body := make([]byte, 0, 2+32+1+len(sessionID))
	body = append(body, 0x03, 0x03)
	body = append(body, make([]byte, 32)...)
	body = append(body, byte(len(sessionID)))
	body = append(body, sessionID...)
	out := make([]byte, 4+len(body))
	out[0] = 0x01
	out[1] = byte(len(body) >> 16)
	out[2] = byte(len(body) >> 8)
	out[3] = byte(len(body))
	copy(out[4:], body)
	return out
}

// BuildCRYPTOFrame wraps data in a single CRYPTO frame with offset 0.
func BuildCRYPTOFrame(data []byte) []byte {
	if VarIntLen(uint64(len(data))) > 2 {
		panic("mirage: CRYPTO data too large for 2-byte length varint")
	}
	out := make([]byte, 0, 4+len(data))
	out = append(out, 0x06, 0x00)
	if VarIntLen(uint64(len(data))) == 1 {
		out = append(out, byte(len(data)))
	} else {
		out = append(out, 0x40|byte(len(data)>>8), byte(len(data)))
	}
	out = append(out, data...)
	return out
}
