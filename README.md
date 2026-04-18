# mirage

A QUIC-based transport that hides as Chrome HTTP/3 traffic to popular CDNs.

Status: pre-alpha. APIs and wire format are unstable.

## Overview

mirage runs over standard QUIC. The handshake puts an authentication
short-id inside the TLS 1.3 `legacy_session_id` field. Unauthenticated
packets are forwarded byte-for-byte to a real CDN endpoint via a
stateless 4-tuple UDP relay, so active probes see the real CDN's
certificate and response.

The data plane is built on a vendored `quic-go` fork (`uquic`, in
`_vendor/`) that ships the Chrome HTTP/3 ClientHello and packet
shape. The congestion controller is whatever that build defaults to
(a naturally oscillating, sawtooth-shaped CC such as CUBIC or BBR —
see `docs/spec.md` §6.1 for why a specific algorithm is not mandated).
Chrome HTTP/3 timings (PING, PMTU, ACK delay) and Chrome's empirical
packet-size distribution are matched on top. Long-lived connections
are rotated at jittered thresholds (default 90-180 min or 3-8 GiB)
to avoid the "single connection, many gigabytes, hours" tell.

See [`docs/spec.md`](./docs/spec.md) for the wire format and full
protocol specification.

## Layout

```
proto/       wire format constants and frame definitions
handshake/   REALITY-over-QUIC handshake + 4-tuple UDP relay
replay/      time-window key derivation
transport/   QUIC Initial-packet helpers used by the dispatcher
behavior/    Chrome HTTP/3 timing and flow-control constants
recycle/     connection rotation
adapter/     interfaces decoupling the protocol from the host system
proxy/       in-band TCP_CONNECT framing on a QUIC stream
client/      mirage QUIC client (thin shim over uquic)
config/      TOML configuration loader
metrics/     pluggable counter / gauge / histogram interface
cmd/         standalone binaries (SOCKS5 client)
examples/    minimal reference server
_vendor/     vendored uquic
docs/        protocol specification and operational notes
```

## Integration

mirage knows nothing about user management or billing. To embed it,
implement three interfaces from [`adapter`](./adapter):

```go
type UserAuthenticator interface {
    Verify(ctx context.Context, shortID []byte) (UserID, error)
}

type TrafficReporter interface {
    Report(ctx context.Context, userID UserID, bytesUp, bytesDown uint64)
}

type SNITargetProvider interface {
    Pool() []string
    ResolveRealTarget(ctx context.Context, sni string) (host string, port uint16, err error)
}
```

A reference server backed by fixed in-memory data lives in
[`examples/minimal-server`](./examples/minimal-server). A SOCKS5
client that tunnels TCP through one mirage connection lives in
[`cmd/mirage-client`](./cmd/mirage-client).

## Build

```
go build ./...
go test ./...
```

Requires Go 1.24 or newer.

## License

MIT. See [LICENSE](./LICENSE).
