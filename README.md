# mirage

A QUIC-based transport that hides as Chrome HTTP/3 traffic to popular CDNs.

Status: pre-alpha. APIs and wire format are unstable.

## Overview

mirage runs over standard QUIC. The handshake puts an authentication
short-id inside the TLS 1.3 `legacy_session_id` field. Unauthenticated
packets are forwarded byte-for-byte to a real CDN endpoint via a
stateless 4-tuple UDP relay, so active probes see the real CDN's
certificate and response.

The data plane uses the host `quic-go` build's default congestion
controller (a naturally oscillating, sawtooth-shaped CC such as CUBIC
or BBR — see `docs/spec.md` §6.1 for why a specific algorithm is not
mandated), Chrome HTTP/3 timings (PING, PMTU, ACK delay), and Chrome's
empirical packet-size distribution. Long-lived
connections are rotated at jittered thresholds (default 90-180 min or
3-8 GiB) to avoid the "single connection, many gigabytes, hours" tell.

See [`docs/spec.md`](./docs/spec.md) for the wire format and full
protocol specification.

## Layout

```
proto/       wire format constants and frame definitions
handshake/   REALITY-over-QUIC handshake + 4-tuple UDP relay
replay/      time-window key derivation + sliding-window anti-replay
transport/   QUIC integration layer
behavior/    Chrome HTTP/3 timing constants
recycle/     connection rotation
adapter/     interfaces decoupling the protocol from the host system
examples/    minimal reference server and client
docs/        protocol specification
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

A reference implementation against fixed in-memory data lives in
[`examples/minimal-server`](./examples/minimal-server).

## Build

```
go build ./...
go test ./...
```

Requires Go 1.24 or newer.

## License

MIT. See [LICENSE](./LICENSE).
