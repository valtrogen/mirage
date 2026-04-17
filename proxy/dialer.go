package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/valtrogen/mirage/client"
)

// Dial opens a stream on conn, sends a TCP_CONNECT request for
// (network, addr), and returns a net.Conn that bridges bytes through
// the stream until either side closes.
//
// network must be "tcp", "tcp4", or "tcp6" — the proxy frame carries
// no AF distinction beyond the address literal, so all three behave
// the same on the wire. addr is parsed with net.SplitHostPort.
//
// The returned net.Conn's LocalAddr is the local UDP address of the
// mirage connection; RemoteAddr is a synthetic address that reports
// the requested target. SetDeadline/SetReadDeadline/SetWriteDeadline
// propagate to the underlying mirage stream.
func Dial(ctx context.Context, conn *client.Conn, network, addr string) (net.Conn, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, &net.OpError{
			Op:  "dial",
			Net: network,
			Err: fmt.Errorf("mirage/proxy: unsupported network %q", network),
		}
	}
	if conn == nil {
		return nil, errors.New("mirage/proxy: nil client.Conn")
	}

	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: err}
	}
	port, err := strconv.ParseUint(portStr, 10, 16)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: fmt.Errorf("invalid port: %w", err)}
	}

	st, err := conn.OpenStream(ctx)
	if err != nil {
		return nil, &net.OpError{Op: "dial", Net: network, Err: err}
	}

	if dl, ok := ctx.Deadline(); ok {
		_ = st.SetDeadline(dl)
		defer st.SetDeadline(time.Time{})
	}

	req := Request{Cmd: CmdTCPConnect, Host: host, Port: uint16(port)}
	if _, err := req.WriteTo(st); err != nil {
		_ = st.Close()
		return nil, &net.OpError{Op: "write", Net: network, Err: err}
	}

	resp, err := ReadResponse(st)
	if err != nil {
		_ = st.Close()
		return nil, &net.OpError{Op: "read", Net: network, Err: err}
	}
	if resp.Status != StatusOK {
		_ = st.Close()
		return nil, &Error{Status: resp.Status, Reason: resp.Reason}
	}

	return &streamConn{
		stream: st,
		local:  conn.LocalAddr(),
		remote: targetAddr{network: network, addr: addr},
	}, nil
}

// streamConn adapts a *client.Stream to net.Conn.
type streamConn struct {
	stream *client.Stream
	local  net.Addr
	remote net.Addr
}

func (c *streamConn) Read(p []byte) (int, error)         { return c.stream.Read(p) }
func (c *streamConn) Write(p []byte) (int, error)        { return c.stream.Write(p) }
func (c *streamConn) Close() error                       { return c.stream.Close() }
func (c *streamConn) LocalAddr() net.Addr                { return c.local }
func (c *streamConn) RemoteAddr() net.Addr               { return c.remote }
func (c *streamConn) SetDeadline(t time.Time) error      { return c.stream.SetDeadline(t) }
func (c *streamConn) SetReadDeadline(t time.Time) error  { return c.stream.SetReadDeadline(t) }
func (c *streamConn) SetWriteDeadline(t time.Time) error { return c.stream.SetWriteDeadline(t) }

// targetAddr reports the mirage proxy's logical destination as a
// net.Addr so callers can log or compare it like any other.
type targetAddr struct {
	network string
	addr    string
}

func (a targetAddr) Network() string { return a.network }
func (a targetAddr) String() string  { return a.addr }
