package transport

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

// QUICv1 is the QUIC version 1 number (RFC 9000).
const QUICv1 uint32 = 0x00000001

// MaxConnectionIDLen bounds the connection IDs accepted from the wire to
// the QUIC v1 limit.
const MaxConnectionIDLen = 20

var (
	// ErrNotInitial is returned when a datagram does not start with a
	// QUIC v1 long-header Initial packet.
	ErrNotInitial = errors.New("mirage: not a QUIC v1 Initial packet")

	// ErrTruncatedPacket is returned when an Initial packet is too short
	// to contain its declared fields.
	ErrTruncatedPacket = errors.New("mirage: truncated Initial packet")

	// ErrAEADAuthFailed is returned when the Initial AEAD tag does not verify.
	ErrAEADAuthFailed = errors.New("mirage: Initial AEAD authentication failed")
)

// Initial is the result of parsing one QUIC v1 Initial packet.
type Initial struct {
	Version      uint32
	DCID         []byte
	SCID         []byte
	Token        []byte
	PacketNumber uint64

	// Payload is the decrypted plaintext of the Initial packet's frames
	// (CRYPTO, PADDING, ACK, ...). It does not include the packet
	// number or AEAD tag.
	Payload []byte

	// PacketLen is the total number of bytes consumed in the input
	// datagram by this Initial packet (header + length-field bytes).
	// Subsequent packets may be coalesced after this offset.
	PacketLen int
}

// ParseInitial decodes the first QUIC v1 Initial packet at the start of
// datagram. It performs header unprotection and AEAD decryption.
//
// On success the returned Initial holds the decrypted plaintext of the
// packet's frames. On failure an error is returned and the caller should
// treat the entire datagram as unauthenticated.
func ParseInitial(datagram []byte) (*Initial, error) {
	if len(datagram) < 7 {
		return nil, ErrTruncatedPacket
	}

	// Long header bit set + fixed bit set; type = Initial (00).
	if datagram[0]&0xC0 != 0xC0 {
		return nil, ErrNotInitial
	}
	if datagram[0]&0x30 != 0x00 {
		return nil, ErrNotInitial
	}

	version := binary.BigEndian.Uint32(datagram[1:5])
	if version != QUICv1 {
		return nil, ErrNotInitial
	}

	off := 5

	if off >= len(datagram) {
		return nil, ErrTruncatedPacket
	}
	dcidLen := int(datagram[off])
	off++
	if dcidLen > MaxConnectionIDLen || off+dcidLen > len(datagram) {
		return nil, ErrTruncatedPacket
	}
	dcid := datagram[off : off+dcidLen]
	off += dcidLen

	if off >= len(datagram) {
		return nil, ErrTruncatedPacket
	}
	scidLen := int(datagram[off])
	off++
	if scidLen > MaxConnectionIDLen || off+scidLen > len(datagram) {
		return nil, ErrTruncatedPacket
	}
	scid := datagram[off : off+scidLen]
	off += scidLen

	tokenLen, n, err := ReadVarInt(datagram[off:])
	if err != nil {
		return nil, ErrTruncatedPacket
	}
	off += n
	if uint64(off)+tokenLen > uint64(len(datagram)) {
		return nil, ErrTruncatedPacket
	}
	token := datagram[off : off+int(tokenLen)]
	off += int(tokenLen)

	payloadLen, n, err := ReadVarInt(datagram[off:])
	if err != nil {
		return nil, ErrTruncatedPacket
	}
	off += n
	pnOffset := off
	if uint64(pnOffset)+payloadLen > uint64(len(datagram)) {
		return nil, ErrTruncatedPacket
	}
	if payloadLen < 20 {
		// Need at least 4 bytes PN + 16 bytes AEAD tag.
		return nil, ErrTruncatedPacket
	}
	totalLen := pnOffset + int(payloadLen)

	// Sample for header protection: 16 bytes at pnOffset+4.
	if pnOffset+4+16 > len(datagram) {
		return nil, ErrTruncatedPacket
	}
	sample := datagram[pnOffset+4 : pnOffset+4+16]

	secrets, err := deriveInitialSecrets(dcid)
	if err != nil {
		return nil, err
	}

	mask, err := computeHeaderMask(secrets.clientHP[:], sample)
	if err != nil {
		return nil, err
	}

	// Make a private mutable copy of the header bytes.
	header := make([]byte, totalLen)
	copy(header, datagram[:totalLen])

	header[0] ^= mask[0] & 0x0F
	pnLen := int(header[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		header[pnOffset+i] ^= mask[1+i]
	}

	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = (pn << 8) | uint64(header[pnOffset+i])
	}

	// Build IV: client_iv XOR (pn padded into low bytes, big-endian).
	var iv [12]byte
	copy(iv[:], secrets.clientIV[:])
	for i := 0; i < 8; i++ {
		iv[12-1-i] ^= byte(pn >> (8 * i))
	}

	block, err := aes.NewCipher(secrets.clientKey[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// AEAD additional data is the unprotected packet header up to the
	// end of the packet number.
	aad := header[:pnOffset+pnLen]
	ciphertext := datagram[pnOffset+pnLen : totalLen]

	plain, err := aead.Open(nil, iv[:], ciphertext, aad)
	if err != nil {
		return nil, ErrAEADAuthFailed
	}

	return &Initial{
		Version:      version,
		DCID:         append([]byte(nil), dcid...),
		SCID:         append([]byte(nil), scid...),
		Token:        append([]byte(nil), token...),
		PacketNumber: pn,
		Payload:      plain,
		PacketLen:    totalLen,
	}, nil
}

// computeHeaderMask returns AES-ECB(hpKey, sample) which is the 5-byte
// header protection mask used by RFC 9001 §5.4.
func computeHeaderMask(hpKey, sample []byte) ([5]byte, error) {
	var out [5]byte
	if len(sample) < aes.BlockSize {
		return out, errors.New("mirage: sample too short")
	}
	block, err := aes.NewCipher(hpKey)
	if err != nil {
		return out, err
	}
	var enc [aes.BlockSize]byte
	block.Encrypt(enc[:], sample[:aes.BlockSize])
	copy(out[:], enc[:5])
	return out, nil
}

// ExtractCRYPTOData walks the QUIC frames in payload and returns the
// contiguous CRYPTO data starting at offset 0. It silently skips PADDING
// (0x00) and PING (0x01) frames. Any unknown frame type or a non-zero
// starting offset stops the walk and returns whatever has been collected
// so far.
func ExtractCRYPTOData(payload []byte) ([]byte, error) {
	var out []byte
	expected := uint64(0)
	for i := 0; i < len(payload); {
		t := payload[i]
		switch t {
		case 0x00:
			i++
		case 0x01:
			i++
		case 0x06:
			i++
			off, n, err := ReadVarInt(payload[i:])
			if err != nil {
				return out, err
			}
			i += n
			length, n, err := ReadVarInt(payload[i:])
			if err != nil {
				return out, err
			}
			i += n
			if uint64(i)+length > uint64(len(payload)) {
				return out, ErrTruncatedPacket
			}
			if off != expected {
				return out, nil
			}
			out = append(out, payload[i:i+int(length)]...)
			expected += length
			i += int(length)
		default:
			return out, nil
		}
	}
	return out, nil
}
