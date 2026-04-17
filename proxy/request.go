package proxy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// ProtoVersion is the version byte at the start of every request and
// response. Bump it whenever an incompatible wire change ships.
const ProtoVersion uint8 = 0x01

// Application stream-error codes the proxy uses when calling
// CancelRead / CancelWrite on a QUIC stream. They occupy a small
// numeric space so they fit comfortably in a varint and are easy to
// recognise in logs and packet captures.
const (
	// ProxyErrIdleTimeout is sent on both halves when the server-side
	// idle watchdog tears a stream down because no bytes flowed for
	// Server.StreamIdleTimeout. The client surfaces this as a
	// recoverable timeout error, not a protocol violation.
	ProxyErrIdleTimeout uint64 = 0x10
)

// Cmd identifies the requested operation.
type Cmd uint8

const (
	// CmdTCPConnect asks the server to dial a TCP target and bridge
	// bytes verbatim until either side closes.
	CmdTCPConnect Cmd = 0x01

	// CmdUDPAssociate asks the server to bind an ephemeral UDP socket
	// that will relay datagrams in both directions for the lifetime
	// of the stream. After the server replies StatusOK both peers
	// exchange length-prefixed UDP frames on the stream (see udp.go).
	//
	// The Host/Port fields of the request are ignored; clients should
	// leave them empty ("0.0.0.0:0").
	CmdUDPAssociate Cmd = 0x02
)

// AddrType identifies the encoding of the address field in a request.
type AddrType uint8

const (
	AddrIPv4   AddrType = 0x01
	AddrDomain AddrType = 0x03
	AddrIPv6   AddrType = 0x04
)

// Status is the response status byte.
type Status uint8

const (
	StatusOK             Status = 0x00
	StatusGeneralFail    Status = 0x01
	StatusNotAllowed     Status = 0x02
	StatusHostUnreach    Status = 0x03
	StatusNetworkUnreach Status = 0x04
	StatusConnRefused    Status = 0x05
	StatusTTLExpired     Status = 0x06
	StatusBadRequest     Status = 0x07
)

// String returns a human-readable label.
func (s Status) String() string {
	switch s {
	case StatusOK:
		return "ok"
	case StatusGeneralFail:
		return "general failure"
	case StatusNotAllowed:
		return "not allowed"
	case StatusHostUnreach:
		return "host unreachable"
	case StatusNetworkUnreach:
		return "network unreachable"
	case StatusConnRefused:
		return "connection refused"
	case StatusTTLExpired:
		return "ttl expired"
	case StatusBadRequest:
		return "bad request"
	default:
		return fmt.Sprintf("status(0x%02x)", uint8(s))
	}
}

// Maximum field lengths. Both addr (when domain) and reason are
// length-prefixed by a single byte, so the natural cap is 255.
const (
	maxDomainLen = 255
	maxReasonLen = 255
)

// ErrProtocol is returned when a peer sends bytes that do not parse as
// a valid request or response.
var ErrProtocol = errors.New("mirage/proxy: protocol error")

// Request is one decoded proxy request.
type Request struct {
	Cmd  Cmd
	Host string
	Port uint16
}

// AppendBytes encodes r and appends it to b.
func (r Request) AppendBytes(b []byte) ([]byte, error) {
	atyp, addr, err := encodeAddr(r.Host)
	if err != nil {
		return nil, err
	}
	b = append(b, ProtoVersion, byte(r.Cmd), byte(atyp))
	b = appendUint16BE(b, r.Port)
	if atyp == AddrDomain {
		b = append(b, byte(len(addr)))
	}
	b = append(b, addr...)
	return b, nil
}

// WriteTo writes the encoded request to w. The return value satisfies
// io.WriterTo.
func (r Request) WriteTo(w io.Writer) (int64, error) {
	buf, err := r.AppendBytes(nil)
	if err != nil {
		return 0, err
	}
	n, err := w.Write(buf)
	return int64(n), err
}

// ReadRequest reads exactly one request from r.
func ReadRequest(r io.Reader) (Request, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Request{}, err
	}
	if hdr[0] != ProtoVersion {
		return Request{}, fmt.Errorf("%w: bad version 0x%02x", ErrProtocol, hdr[0])
	}
	req := Request{
		Cmd:  Cmd(hdr[1]),
		Port: binary.BigEndian.Uint16(hdr[3:5]),
	}
	atyp := AddrType(hdr[2])

	switch atyp {
	case AddrIPv4:
		var raw [net.IPv4len]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return Request{}, err
		}
		req.Host = net.IP(raw[:]).String()
	case AddrIPv6:
		var raw [net.IPv6len]byte
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return Request{}, err
		}
		req.Host = net.IP(raw[:]).String()
	case AddrDomain:
		var lb [1]byte
		if _, err := io.ReadFull(r, lb[:]); err != nil {
			return Request{}, err
		}
		if lb[0] == 0 {
			return Request{}, fmt.Errorf("%w: empty domain", ErrProtocol)
		}
		buf := make([]byte, lb[0])
		if _, err := io.ReadFull(r, buf); err != nil {
			return Request{}, err
		}
		req.Host = string(buf)
	default:
		return Request{}, fmt.Errorf("%w: unknown addr type 0x%02x", ErrProtocol, atyp)
	}
	return req, nil
}

// Response is one decoded proxy response.
type Response struct {
	Status Status
	Reason string
}

// AppendBytes encodes resp and appends it to b. Reason is silently
// truncated at maxReasonLen bytes; callers that care about the exact
// text should pre-trim.
func (r Response) AppendBytes(b []byte) []byte {
	reason := r.Reason
	if len(reason) > maxReasonLen {
		reason = reason[:maxReasonLen]
	}
	b = append(b, ProtoVersion, byte(r.Status), byte(len(reason)))
	b = append(b, reason...)
	return b
}

// WriteTo writes the encoded response to w.
func (r Response) WriteTo(w io.Writer) (int64, error) {
	buf := r.AppendBytes(nil)
	n, err := w.Write(buf)
	return int64(n), err
}

// ReadResponse reads exactly one response from r.
func ReadResponse(r io.Reader) (Response, error) {
	var hdr [3]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return Response{}, err
	}
	if hdr[0] != ProtoVersion {
		return Response{}, fmt.Errorf("%w: bad version 0x%02x", ErrProtocol, hdr[0])
	}
	resp := Response{Status: Status(hdr[1])}
	if hdr[2] > 0 {
		buf := make([]byte, hdr[2])
		if _, err := io.ReadFull(r, buf); err != nil {
			return Response{}, err
		}
		resp.Reason = string(buf)
	}
	return resp, nil
}

// Error is returned to callers of Dial when the server rejects the
// request with a non-OK status. It satisfies the error interface and
// carries the structured status for programmatic checks.
type Error struct {
	Status Status
	Reason string
}

// Error implements error.
func (e *Error) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("mirage/proxy: %s: %s", e.Status, e.Reason)
	}
	return fmt.Sprintf("mirage/proxy: %s", e.Status)
}

func encodeAddr(host string) (AddrType, []byte, error) {
	if host == "" {
		return 0, nil, fmt.Errorf("%w: empty host", ErrProtocol)
	}
	if ip := net.ParseIP(host); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			return AddrIPv4, v4, nil
		}
		return AddrIPv6, ip.To16(), nil
	}
	if len(host) > maxDomainLen {
		return 0, nil, fmt.Errorf("%w: domain length %d > %d", ErrProtocol, len(host), maxDomainLen)
	}
	return AddrDomain, []byte(host), nil
}

func appendUint16BE(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}
