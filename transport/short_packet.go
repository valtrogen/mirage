package transport

import (
	"errors"
)

// ErrNotShortHeader is returned when the parser is given a packet whose
// first byte does not match the QUIC v1 short-header signature.
var ErrNotShortHeader = errors.New("mirage: not a short-header packet")

// ShortHeaderPacket holds the parsed plaintext of a 1-RTT packet.
type ShortHeaderPacket struct {
	KeyPhase     bool
	PacketNumber uint64
	Payload      []byte
	PacketLen    int
}

// ParseShortHeader decodes a single 1-RTT packet at the start of
// datagram. The receiver must know the local DCID length out of band
// (RFC 9000 §17.2 Note: short headers omit a connection ID length).
func ParseShortHeader(datagram []byte, dcidLen int, pp *PacketProtection) (*ShortHeaderPacket, error) {
	if len(datagram) < 1+dcidLen+4+16 {
		return nil, ErrShortPacket
	}
	if datagram[0]&0xC0 != 0x40 {
		return nil, ErrNotShortHeader
	}
	pnOffset := 1 + dcidLen
	if pnOffset+4+16 > len(datagram) {
		return nil, ErrShortPacket
	}
	sample := datagram[pnOffset+4 : pnOffset+4+16]
	mask := pp.HeaderMask(sample)

	header := make([]byte, len(datagram))
	copy(header, datagram)

	header[0] ^= mask[0] & 0x1F
	pnLen := int(header[0]&0x03) + 1
	for i := 0; i < pnLen; i++ {
		header[pnOffset+i] ^= mask[1+i]
	}

	var pn uint64
	for i := 0; i < pnLen; i++ {
		pn = (pn << 8) | uint64(header[pnOffset+i])
	}
	keyPhase := header[0]&0x04 != 0

	iv := make([]byte, len(pp.IV))
	copy(iv, pp.IV)
	for i := 0; i < 8; i++ {
		iv[len(iv)-1-i] ^= byte(pn >> (8 * i))
	}

	aad := header[:pnOffset+pnLen]
	ciphertext := datagram[pnOffset+pnLen:]
	plain, err := pp.AEAD.Open(nil, iv, ciphertext, aad)
	if err != nil {
		return nil, ErrAEADAuthFailed
	}
	return &ShortHeaderPacket{
		KeyPhase:     keyPhase,
		PacketNumber: pn,
		Payload:      plain,
		PacketLen:    len(datagram),
	}, nil
}

// BuildShortHeader constructs a single 1-RTT packet. The packet number
// is encoded in 4 bytes; this matches BuildLongHeader and keeps the
// minimal client simple.
func BuildShortHeader(dcid []byte, packetNumber uint32, plaintext []byte, keyPhase bool, pp *PacketProtection) ([]byte, error) {
	if len(dcid) > MaxConnectionIDLen {
		return nil, errors.New("mirage: connection id exceeds 20 bytes")
	}
	const pnLen = 4
	first := byte(0x40) | byte(pnLen-1)
	if keyPhase {
		first |= 0x04
	}
	header := []byte{first}
	header = append(header, dcid...)
	pnOffset := len(header)
	header = append(header,
		byte(packetNumber>>24),
		byte(packetNumber>>16),
		byte(packetNumber>>8),
		byte(packetNumber),
	)

	iv := make([]byte, len(pp.IV))
	copy(iv, pp.IV)
	for i := 0; i < 8; i++ {
		iv[len(iv)-1-i] ^= byte(uint64(packetNumber) >> (8 * i))
	}

	aad := append([]byte(nil), header...)
	ct := pp.AEAD.Seal(nil, iv, plaintext, aad)
	pkt := append(header, ct...)
	if len(pkt) < pnOffset+4+16 {
		return nil, errors.New("mirage: packet too short for header protection sample")
	}
	sample := pkt[pnOffset+4 : pnOffset+4+16]
	mask := pp.HeaderMask(sample)
	pkt[0] ^= mask[0] & 0x1F
	for i := 0; i < pnLen; i++ {
		pkt[pnOffset+i] ^= mask[1+i]
	}
	return pkt, nil
}
