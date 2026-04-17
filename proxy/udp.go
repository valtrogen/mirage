package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// MaxUDPFrameBody bounds the application payload of a single
// stream-carried UDP frame. The chosen limit fits two safety margins:
//   - The worst-case IPv6 datagram payload (65 487 bytes after a 40
//     byte header on a 65 535 byte IP packet) plus our own framing.
//   - Two bytes of length prefix at the wire: the frame's TotalLen is
//     a uint16, so the absolute ceiling is 65 535 minus the address
//     header.
//
// Senders MUST NOT exceed the limit; receivers treat oversize frames
// as protocol errors.
const MaxUDPFrameBody = 64 * 1024

// ErrUDPFrameTooLarge is returned when AppendUDPFrame is asked to
// encode a payload that would push the on-wire frame above the uint16
// length cap.
var ErrUDPFrameTooLarge = fmt.Errorf("mirage/proxy: UDP frame body exceeds %d bytes", MaxUDPFrameBody)

// UDPFrame is one decoded datagram travelling over a UDP-associate
// stream.
//
// On the client→server direction, Host/Port name the destination the
// client wants the server to forward the payload to. On the server→
// client direction, they name the upstream that produced the payload.
type UDPFrame struct {
	Host    string
	Port    uint16
	Payload []byte
}

// On-wire layout of a single UDP frame:
//
//   +----+----+----+----+----+----+----+----+----+----+
//   | TotalLen (BE16)   | ATY |   Address bytes...    |
//   +-------------------+-----+-----------------------+
//   |   Port (BE16)     |        Payload bytes...     |
//   +-------------------+-----------------------------+
//
// TotalLen is the byte count of everything after itself, i.e. the
// sum of (1 + addrLen + 2 + len(Payload)). For ATY=AddrDomain the
// addrLen byte is included as part of "Address bytes" — the layout
// matches §6 of RFC 1928 with the RSV/FRAG bytes omitted because
// mirage's stream is already reliable + ordered.
const udpFrameHeaderMin = 2 + 1 + 2 // length + atyp + port

// AppendUDPFrame serialises f and appends it to b. It is allocation-
// free relative to b's tail.
func AppendUDPFrame(b []byte, f UDPFrame) ([]byte, error) {
	atyp, addr, err := encodeAddr(f.Host)
	if err != nil {
		return nil, err
	}
	addrLen := len(addr)
	if atyp == AddrDomain {
		addrLen++ // length prefix byte
	}
	bodyLen := 1 + addrLen + 2 + len(f.Payload)
	if bodyLen > 0xFFFF || len(f.Payload) > MaxUDPFrameBody {
		return nil, ErrUDPFrameTooLarge
	}
	b = appendUint16BE(b, uint16(bodyLen))
	b = append(b, byte(atyp))
	if atyp == AddrDomain {
		b = append(b, byte(len(addr)))
	}
	b = append(b, addr...)
	b = appendUint16BE(b, f.Port)
	b = append(b, f.Payload...)
	return b, nil
}

// ReadUDPFrame reads exactly one UDP frame from r. The returned
// UDPFrame.Payload is freshly allocated and safe to retain.
func ReadUDPFrame(r io.Reader) (UDPFrame, error) {
	var lenBuf [2]byte
	if _, err := io.ReadFull(r, lenBuf[:]); err != nil {
		return UDPFrame{}, err
	}
	total := int(binary.BigEndian.Uint16(lenBuf[:]))
	if total < 1+1+2 { // smallest valid: ATY + 1-byte addr + port
		return UDPFrame{}, fmt.Errorf("%w: udp frame total %d too short", ErrProtocol, total)
	}
	body := make([]byte, total)
	if _, err := io.ReadFull(r, body); err != nil {
		return UDPFrame{}, err
	}
	atyp := AddrType(body[0])
	pos := 1
	var host string
	switch atyp {
	case AddrIPv4:
		if total < 1+net.IPv4len+2 {
			return UDPFrame{}, fmt.Errorf("%w: udp frame ipv4 too short", ErrProtocol)
		}
		host = net.IP(body[pos : pos+net.IPv4len]).String()
		pos += net.IPv4len
	case AddrIPv6:
		if total < 1+net.IPv6len+2 {
			return UDPFrame{}, fmt.Errorf("%w: udp frame ipv6 too short", ErrProtocol)
		}
		host = net.IP(body[pos : pos+net.IPv6len]).String()
		pos += net.IPv6len
	case AddrDomain:
		if total < 1+1+2 {
			return UDPFrame{}, fmt.Errorf("%w: udp frame domain too short", ErrProtocol)
		}
		dn := int(body[pos])
		pos++
		if dn == 0 || pos+dn+2 > total {
			return UDPFrame{}, fmt.Errorf("%w: udp frame bad domain len", ErrProtocol)
		}
		host = string(body[pos : pos+dn])
		pos += dn
	default:
		return UDPFrame{}, fmt.Errorf("%w: udp frame unknown atyp 0x%02x", ErrProtocol, atyp)
	}
	if pos+2 > total {
		return UDPFrame{}, fmt.Errorf("%w: udp frame truncated", ErrProtocol)
	}
	port := binary.BigEndian.Uint16(body[pos : pos+2])
	pos += 2
	payload := make([]byte, total-pos)
	copy(payload, body[pos:])
	return UDPFrame{Host: host, Port: port, Payload: payload}, nil
}

// ErrUDPClosed is returned by client read paths when the underlying
// stream returned EOF. It mirrors the convention of net.ErrClosed for
// callers that want to distinguish a peer-side close from any other
// error.
var ErrUDPClosed = errors.New("mirage/proxy: udp association closed")
