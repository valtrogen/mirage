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
// datagram with a single key. The keyPhase bit is parsed and exposed
// on the returned ShortHeaderPacket but not enforced — the caller is
// responsible for any key-update bookkeeping.
//
// Use ParseShortHeaderWithUpdate when running against a peer that
// can rotate keys mid-connection (RFC 9001 §6).
func ParseShortHeader(datagram []byte, dcidLen int, pp *PacketProtection) (*ShortHeaderPacket, error) {
	if pp == nil {
		return nil, errors.New("mirage: nil protection")
	}
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

// ParseShortHeaderWithUpdate decodes a 1-RTT packet, transparently
// switching between current and next keys when the peer signals a key
// update via the key-phase bit (RFC 9001 §6).
//
//   - current is the PacketProtection currently in use for the
//     receive direction (key phase == currentPhase).
//   - next is the PacketProtection prepared for the next key phase
//     (key phase == !currentPhase). May be nil before the 1-RTT
//     secrets are pre-derived; in that case packets that signal a
//     key update are rejected with ErrAEADAuthFailed.
//
// Header protection (RFC 9001 §5.4) does not change across key
// updates, so the caller's current.HeaderMask is always used. The
// usedNext return tells the caller whether the AEAD key flipped so
// it can promote next → current and prepare a new next.
func ParseShortHeaderWithUpdate(datagram []byte, dcidLen int, current, next *PacketProtection, currentPhase bool) (*ShortHeaderPacket, bool, error) {
	if current == nil {
		return nil, false, errors.New("mirage: nil current protection")
	}
	if len(datagram) < 1+dcidLen+4+16 {
		return nil, false, ErrShortPacket
	}
	if datagram[0]&0xC0 != 0x40 {
		return nil, false, ErrNotShortHeader
	}
	pnOffset := 1 + dcidLen
	if pnOffset+4+16 > len(datagram) {
		return nil, false, ErrShortPacket
	}
	sample := datagram[pnOffset+4 : pnOffset+4+16]
	mask := current.HeaderMask(sample)

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

	pp := current
	usedNext := false
	if keyPhase != currentPhase {
		if next == nil {
			return nil, false, ErrAEADAuthFailed
		}
		pp = next
		usedNext = true
	}

	iv := make([]byte, len(pp.IV))
	copy(iv, pp.IV)
	for i := 0; i < 8; i++ {
		iv[len(iv)-1-i] ^= byte(pn >> (8 * i))
	}

	aad := header[:pnOffset+pnLen]
	ciphertext := datagram[pnOffset+pnLen:]
	plain, err := pp.AEAD.Open(nil, iv, ciphertext, aad)
	if err != nil {
		return nil, false, ErrAEADAuthFailed
	}
	return &ShortHeaderPacket{
		KeyPhase:     keyPhase,
		PacketNumber: pn,
		Payload:      plain,
		PacketLen:    len(datagram),
	}, usedNext, nil
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
