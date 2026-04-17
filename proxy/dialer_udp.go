package proxy

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valtrogen/mirage/client"
)

// DialPacket opens a CmdUDPAssociate stream on conn and returns a
// net.PacketConn whose WriteTo / ReadFrom encapsulate UDP datagrams
// in mirage UDP frames.
//
// The returned conn is bound to a single mirage stream: closing it
// closes the stream and tears down the server-side UDP socket. There
// is no notion of a "local UDP address" — LocalAddr reports the
// underlying mirage connection's local UDP address purely for
// debugging convenience.
func DialPacket(ctx context.Context, conn *client.Conn) (net.PacketConn, error) {
	if conn == nil {
		return nil, errors.New("mirage/proxy: nil client.Conn")
	}
	st, err := conn.OpenStream(ctx)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: "udp", Err: err}
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
		defer st.SetDeadline(time.Time{})
	}

	// The Host/Port fields are ignored by the server for
	// CmdUDPAssociate but the encoder requires a non-empty host;
	// pass the unspecified IPv4 sentinel.
	req := Request{Cmd: CmdUDPAssociate, Host: "0.0.0.0", Port: 0}
	if _, err := req.WriteTo(st); err != nil {
		_ = st.Close()
		return nil, &net.OpError{Op: "write", Net: "udp", Err: err}
	}
	resp, err := ReadResponse(st)
	if err != nil {
		_ = st.Close()
		return nil, &net.OpError{Op: "read", Net: "udp", Err: err}
	}
	if resp.Status != StatusOK {
		_ = st.Close()
		return nil, &Error{Status: resp.Status, Reason: resp.Reason}
	}

	pc := &packetConn{
		stream:   st,
		reader:   bufio.NewReader(st),
		local:    conn.LocalAddr(),
		readDone: make(chan struct{}),
	}
	return pc, nil
}

// packetConn adapts a UDP-associate stream to net.PacketConn.
//
// Reads pull one UDPFrame at a time off the stream; writes serialise
// each call into a single frame. Frame boundaries are preserved end
// to end so callers see the exact datagrams the upstream emitted.
type packetConn struct {
	stream *client.Stream
	reader *bufio.Reader

	local net.Addr

	closed   atomic.Bool
	closeMu  sync.Mutex
	readDone chan struct{}

	writeMu sync.Mutex
}

// proxyUDPAddr satisfies net.Addr without invoking the resolver.
type proxyUDPAddr struct {
	host string
	port uint16
}

func (a *proxyUDPAddr) Network() string { return "udp" }
func (a *proxyUDPAddr) String() string {
	return net.JoinHostPort(a.host, strconv.Itoa(int(a.port)))
}

// ReadFrom blocks until one UDP frame arrives.
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if p.closed.Load() {
		return 0, nil, net.ErrClosed
	}
	frame, err := ReadUDPFrame(p.reader)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, nil, ErrUDPClosed
		}
		return 0, nil, err
	}
	n := copy(b, frame.Payload)
	return n, &proxyUDPAddr{host: frame.Host, port: frame.Port}, nil
}

// WriteTo frames p as a single mirage UDP packet directed at addr.
// addr may be a *net.UDPAddr or *proxyUDPAddr; any other concrete
// type causes ErrUnsupportedAddr.
func (p *packetConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if p.closed.Load() {
		return 0, net.ErrClosed
	}
	host, port, err := splitAddr(addr)
	if err != nil {
		return 0, err
	}
	out, err := AppendUDPFrame(nil, UDPFrame{Host: host, Port: port, Payload: b})
	if err != nil {
		return 0, err
	}
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if _, err := p.stream.Write(out); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Close shuts the underlying stream and unblocks any pending Reads.
func (p *packetConn) Close() error {
	p.closeMu.Lock()
	defer p.closeMu.Unlock()
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	return p.stream.Close()
}

func (p *packetConn) LocalAddr() net.Addr               { return p.local }
func (p *packetConn) SetDeadline(t time.Time) error      { return p.stream.SetDeadline(t) }
func (p *packetConn) SetReadDeadline(t time.Time) error  { return p.stream.SetReadDeadline(t) }
func (p *packetConn) SetWriteDeadline(t time.Time) error { return p.stream.SetWriteDeadline(t) }

// ErrUnsupportedAddr is returned by WriteTo when given a net.Addr the
// proxy package cannot interpret.
var ErrUnsupportedAddr = errors.New("mirage/proxy: unsupported net.Addr")

func splitAddr(a net.Addr) (string, uint16, error) {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.IP.String(), uint16(v.Port), nil
	case *proxyUDPAddr:
		return v.host, v.port, nil
	default:
		host, portStr, err := net.SplitHostPort(a.String())
		if err != nil {
			return "", 0, fmt.Errorf("%w: %v", ErrUnsupportedAddr, err)
		}
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return "", 0, fmt.Errorf("%w: bad port", ErrUnsupportedAddr)
		}
		return host, uint16(port), nil
	}
}
