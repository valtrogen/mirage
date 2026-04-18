package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// The builders in this file exist purely to drive tests and fuzzing.
// Production code never has to construct an Initial packet by hand:
// the client dials through the upstream uquic stack, and the server
// only ever parses inbound packets.

// BuildClientHelloHandshake returns a single TLS Handshake message
// (msg_type=ClientHello) whose legacy_session_id is set to sid. The
// rest of the ClientHello is the bare minimum to round-trip through
// our parser — TLS structurally valid but not negotiable.
//
// The output is the unwrapped TLS handshake stream as it would appear
// inside a CRYPTO frame.
func BuildClientHelloHandshake(sid []byte) []byte {
	// TLS Handshake header: msg_type(1) + length(3).
	body := buildClientHelloBody(sid)
	hdr := []byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(hdr, body...)
}

func buildClientHelloBody(sid []byte) []byte {
	var out []byte
	out = append(out, 0x03, 0x03)             // legacy_version = TLS 1.2
	out = append(out, make([]byte, 32)...)    // random
	out = append(out, byte(len(sid)))         // legacy_session_id length
	out = append(out, sid...)                 // legacy_session_id
	out = append(out, 0x00, 0x02, 0x13, 0x01) // cipher_suites: TLS_AES_128_GCM_SHA256
	out = append(out, 0x01, 0x00)             // compression_methods: null
	out = append(out, 0x00, 0x00)             // extensions length = 0
	return out
}

// BuildCRYPTOFrame wraps data in a single CRYPTO frame at offset 0.
func BuildCRYPTOFrame(data []byte) []byte {
	out := []byte{0x06}
	out = AppendVarInt(out, 0)
	out = AppendVarInt(out, uint64(len(data)))
	out = append(out, data...)
	return out
}

// BuildInitial assembles a QUIC v1 Initial packet whose payload is
// frames (CRYPTO + PADDING etc.), pads it to padTo bytes, and applies
// header protection + AEAD encryption with the Initial keys derived
// from dcid.
//
// scid may be nil. pn is the truncated 4-byte packet number on the
// wire. padTo is the total UDP datagram size; if it is smaller than
// the natural encoded size, no padding is added.
func BuildInitial(dcid, scid []byte, pn uint32, frames []byte, padTo int) ([]byte, error) {
	if len(dcid) > MaxConnectionIDLen {
		return nil, errors.New("mirage: DCID too long")
	}

	secrets, err := deriveInitialSecrets(dcid)
	if err != nil {
		return nil, err
	}

	// Compose plaintext payload (will be padded inside the AEAD).
	pnBytes := []byte{
		byte(pn >> 24),
		byte(pn >> 16),
		byte(pn >> 8),
		byte(pn),
	}
	plaintext := append([]byte(nil), frames...)
	// Pad payload so the total datagram reaches padTo.
	header := composeInitialHeader(dcid, scid, pn, len(plaintext))
	encoded := len(header) + len(plaintext) + 16 // +tag
	if padTo > encoded {
		padding := make([]byte, padTo-encoded)
		plaintext = append(plaintext, padding...)
		header = composeInitialHeader(dcid, scid, pn, len(plaintext))
	}

	// AEAD nonce: client_iv XOR pn (big-endian, right-aligned).
	var iv [12]byte
	copy(iv[:], secrets.clientIV[:])
	for i := 0; i < 4; i++ {
		iv[12-1-i] ^= pnBytes[3-i]
	}
	block, err := aes.NewCipher(secrets.clientKey[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	ct := aead.Seal(nil, iv[:], plaintext, header)

	// Header protection: 16-byte sample at pn+4.
	pnOffset := len(header) - 4
	sampleStart := pnOffset + 4
	pkt := append(append([]byte{}, header...), ct...)
	if sampleStart+16 > len(pkt) {
		return nil, errors.New("mirage: payload too short for HP sample")
	}
	mask, err := computeHeaderMask(secrets.clientHP[:], pkt[sampleStart:sampleStart+16])
	if err != nil {
		return nil, err
	}
	pkt[0] ^= mask[0] & 0x0F
	for i := 0; i < 4; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt, nil
}

// composeInitialHeader builds the long-header bytes for an Initial
// packet whose plaintext payload (before AEAD tag) has length
// payloadLen and whose packet number is encoded as 4 bytes.
//
// The first byte is left in its protected form (bit 0..3 are the
// reserved/PN fields that header protection will mask in).
func composeInitialHeader(dcid, scid []byte, pn uint32, payloadLen int) []byte {
	first := byte(0xC0) | 0x03 // long + fixed; type=Initial; pn_len=4
	out := []byte{first}
	out = binary.BigEndian.AppendUint32(out, QUICv1)
	out = append(out, byte(len(dcid)))
	out = append(out, dcid...)
	out = append(out, byte(len(scid)))
	out = append(out, scid...)
	out = AppendVarInt(out, 0) // empty token
	// Length = pn(4) + payload + AEAD tag(16).
	out = AppendVarInt(out, uint64(4+payloadLen+16))
	out = append(out, byte(pn>>24), byte(pn>>16), byte(pn>>8), byte(pn))
	return out
}
