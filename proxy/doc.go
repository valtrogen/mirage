// Package proxy turns mirage QUIC streams into bidirectional bridges
// to outbound TCP targets.
//
// On the wire, a freshly opened bidi stream begins with a tiny request
// frame that names the destination (cmd, host, port). The server
// replies with a one-byte status plus an optional reason string, and
// from that point on the stream carries application bytes verbatim.
// The full layout is described in docs/spec.md and in request.go.
//
// Two entry points cover both ends:
//
//   - Server.Serve binds a *handshake.Conn to outbound TCP. One Server
//     instance is safe for concurrent reuse across many connections.
//   - Dial wraps client.Conn.OpenStream + the request codec and returns
//     a net.Conn that callers can hand to existing TCP code.
//
// UDP support is not yet implemented; a UDP_BIND command exists in the
// codec for forward compatibility but the server rejects it.
package proxy
