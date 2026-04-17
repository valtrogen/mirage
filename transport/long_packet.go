package transport

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
)

// LongPacketType identifies the four QUIC v1 long-header packet types
// per RFC 9000 §17.2.
type LongPacketType uint8

const (
	LongPacketTypeInitial   LongPacketType = 0x00
	LongPacketType0RTT      LongPacketType = 0x01
	LongPacketTypeHandshake LongPacketType = 0x02
	LongPacketTypeRetry     LongPacketType = 0x03
)

// LongHeaderPacket holds the parsed plaintext of a QUIC v1 long-header
// packet (Initial, Handshake, or 0-RTT). Token is non-nil only for
// Initial packets.
type LongHeaderPacket struct {
	Type         LongPacketType
	Version      uint32
	DCID         []byte
	SCID         []byte
	Token        []byte
	PacketNumber uint64
	Payload      []byte
	PacketLen    int
}

// ErrShortPacket is returned when a buffer is shorter than the QUIC v1
// long header demands.
var ErrShortPacket = errors.New("mirage: short QUIC long-header packet")

// DeriveClientInitialProtection derives the client-direction Initial
// protection (client → server) from dcid per RFC 9001 §5.2.
func DeriveClientInitialProtection(dcid []byte) (*PacketProtection, error) {
	return deriveInitialProtection(dcid, "client in")
}

// DeriveServerInitialProtection derives the server-direction Initial
// protection (server → client) from dcid per RFC 9001 §5.2.
func DeriveServerInitialProtection(dcid []byte) (*PacketProtection, error) {
	return deriveInitialProtection(dcid, "server in")
}

func deriveInitialProtection(dcid []byte, label string) (*PacketProtection, error) {
	prk, err := hkdf.Extract(sha256.New, dcid, quicV1InitialSalt)
	if err != nil {
		return nil, err
	}
	secret, err := hkdfExpandLabel(prk, label, 32)
	if err != nil {
		return nil, err
	}
	return DerivePacketProtection(CipherSuiteAES128GCMSHA256, secret)
}

// ParseLongHeader decodes the first long-header packet at the start of
// datagram using pp. The function performs header unprotection and AEAD
// decryption. Coalesced packets that may follow are not consumed.
func ParseLongHeader(datagram []byte, pp *PacketProtection) (*LongHeaderPacket, error) {
	if len(datagram) < 7 {
		return nil, ErrShortPacket
	}
	if datagram[0]&0xC0 != 0xC0 {
		return nil, fmt.Errorf("mirage: not a long-header packet (first byte 0x%x)", datagram[0])
	}

	t := LongPacketType((datagram[0] & 0x30) >> 4)
	version := binary.BigEndian.Uint32(datagram[1:5])

	off := 5
	if off >= len(datagram) {
		return nil, ErrShortPacket
	}
	dcidLen := int(datagram[off])
	off++
	if dcidLen > MaxConnectionIDLen || off+dcidLen > len(datagram) {
		return nil, ErrShortPacket
	}
	dcid := datagram[off : off+dcidLen]
	off += dcidLen

	if off >= len(datagram) {
		return nil, ErrShortPacket
	}
	scidLen := int(datagram[off])
	off++
	if scidLen > MaxConnectionIDLen || off+scidLen > len(datagram) {
		return nil, ErrShortPacket
	}
	scid := datagram[off : off+scidLen]
	off += scidLen

	var token []byte
	if t == LongPacketTypeInitial {
		tlen, n, err := ReadVarInt(datagram[off:])
		if err != nil {
			return nil, err
		}
		off += n
		if uint64(off)+tlen > uint64(len(datagram)) {
			return nil, ErrShortPacket
		}
		token = datagram[off : off+int(tlen)]
		off += int(tlen)
	}

	plen, n, err := ReadVarInt(datagram[off:])
	if err != nil {
		return nil, err
	}
	off += n
	pnOffset := off
	if uint64(pnOffset)+plen > uint64(len(datagram)) {
		return nil, ErrShortPacket
	}
	if plen < 20 {
		return nil, ErrShortPacket
	}
	totalLen := pnOffset + int(plen)

	if pnOffset+4+16 > len(datagram) {
		return nil, ErrShortPacket
	}
	sample := datagram[pnOffset+4 : pnOffset+4+16]
	mask := pp.HeaderMask(sample)

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

	iv := make([]byte, len(pp.IV))
	copy(iv, pp.IV)
	for i := 0; i < 8; i++ {
		iv[len(iv)-1-i] ^= byte(pn >> (8 * i))
	}

	aad := header[:pnOffset+pnLen]
	ciphertext := datagram[pnOffset+pnLen : totalLen]

	plain, err := pp.AEAD.Open(nil, iv, ciphertext, aad)
	if err != nil {
		return nil, ErrAEADAuthFailed
	}

	return &LongHeaderPacket{
		Type:         t,
		Version:      version,
		DCID:         append([]byte(nil), dcid...),
		SCID:         append([]byte(nil), scid...),
		Token:        append([]byte(nil), token...),
		PacketNumber: pn,
		Payload:      plain,
		PacketLen:    totalLen,
	}, nil
}

// BuildLongHeader constructs a single long-header packet of type t.
//
// For Initial packets, token may be empty or nil. For Handshake / 0-RTT
// packets, token must be nil.
//
// padToLen, if greater than the natural packet length, appends PADDING
// frames to the plaintext to bring the encoded packet up to padToLen
// bytes (used to satisfy the 1200-byte client Initial requirement of
// RFC 9000 §14.1).
//
// packetNumber is encoded with the same byte length used in
// transport/initial_build.go (currently fixed at 4 bytes); callers that
// need to manage truncated PNs should encode packets manually.
func BuildLongHeader(
	t LongPacketType,
	version uint32,
	dcid, scid, token []byte,
	packetNumber uint32,
	plaintext []byte,
	padToLen int,
	pp *PacketProtection,
) ([]byte, error) {
	if t == LongPacketTypeRetry {
		return nil, errors.New("mirage: Retry packets are not built by this helper")
	}
	if t != LongPacketTypeInitial && len(token) != 0 {
		return nil, errors.New("mirage: token only allowed on Initial packets")
	}
	if len(dcid) > MaxConnectionIDLen || len(scid) > MaxConnectionIDLen {
		return nil, errors.New("mirage: connection id exceeds 20 bytes")
	}

	const pnLen = 4
	first := byte(0xC0) | (byte(t)&0x03)<<4 | byte(pnLen-1)

	header := []byte{first}
	var versionBytes [4]byte
	binary.BigEndian.PutUint32(versionBytes[:], version)
	header = append(header, versionBytes[:]...)
	header = append(header, byte(len(dcid)))
	header = append(header, dcid...)
	header = append(header, byte(len(scid)))
	header = append(header, scid...)
	if t == LongPacketTypeInitial {
		header = AppendVarInt(header, uint64(len(token)))
		header = append(header, token...)
	}

	body := plaintext
	if padToLen > 0 {
		const tagLen = 16
		approx := len(header) + 2 + pnLen + len(body) + tagLen
		if approx < padToLen {
			body = append([]byte(nil), body...)
			body = AppendPaddingFrames(body, padToLen-approx)
		}
	}

	payloadLen := pnLen + len(body) + 16
	header = AppendVarInt(header, uint64(payloadLen))

	pnBytes := []byte{
		byte(packetNumber >> 24),
		byte(packetNumber >> 16),
		byte(packetNumber >> 8),
		byte(packetNumber),
	}
	header = append(header, pnBytes...)

	pnOffset := len(header) - pnLen

	iv := make([]byte, len(pp.IV))
	copy(iv, pp.IV)
	for i := 0; i < 8; i++ {
		iv[len(iv)-1-i] ^= byte(uint64(packetNumber) >> (8 * i))
	}

	aad := append([]byte(nil), header...)
	ct := pp.AEAD.Seal(nil, iv, body, aad)

	pkt := append(header, ct...)
	if len(pkt) < pnOffset+4+16 {
		return nil, errors.New("mirage: packet too short for header protection sample")
	}
	sample := pkt[pnOffset+4 : pnOffset+4+16]
	mask := pp.HeaderMask(sample)

	pkt[0] ^= mask[0] & 0x0F
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt, nil
}
