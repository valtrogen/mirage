# mirage Protocol Specification

Version: `mirage/0.1` (pre-alpha; wire format subject to change).

This document specifies the wire format, handshake state machine,
anti-replay rules and data-plane constraints. Normative requirements
use the keywords from RFC 2119.

## 1. Goals

1. The on-wire bytes match a Chrome HTTP/3 connection to a major CDN.
2. Active probes that fail authentication are forwarded to a real CDN
   endpoint; the prober receives the real CDN's response.
3. Stale-window replays are rejected without allocating QUIC state.
4. Single-connection throughput stays at standard BBRv2 levels.
5. The protocol depends only on the three interfaces in `adapter`.

## 2. Cryptographic Primitives

| Purpose                  | Algorithm                                |
| ------------------------ | ---------------------------------------- |
| Master-key derivation    | HKDF-SHA256                              |
| Short-id confidentiality | AES-128-GCM                              |
| Stream confidentiality   | inherited from QUIC AEAD (RFC 9001)      |
| TLS handshake            | TLS 1.3 (RFC 8446) inside QUIC v1        |

`master_key` is a 32-byte secret distributed out of band to each client.

The L1 time-window key is derived as

```
window_key(t) = HKDF-Expand(
    HKDF-Extract(salt = MasterKeySalt, ikm = master_key),
    info = "mirage v1 window" || u64_be(t),
    L = 16
)
```

with `t = floor(unix_time / WindowSeconds)` and `WindowSeconds = 90`.

## 3. Handshake

### 3.1 Short-id encoding

The 32-byte TLS 1.3 ClientHello `legacy_session_id` field carries:

```
offset  size  field
     0     4  WindowID  (big-endian uint32, low 32 bits of t)
     4     8  ShortID   (AES-128-GCM ciphertext)
    12     4  Nonce     (per-handshake random)
    16    16  AuthTag   (AES-128-GCM tag over bytes 0..16)
```

Encryption:

```
ct, tag = AES-128-GCM-Encrypt(
    key   = window_key(t),
    iv    = WindowID || Nonce || zero(4),   // 12 bytes
    aad   = WindowID,                       // 4 bytes
    ptxt  = ShortID                         // 8 bytes
)
```

Bytes 4..12 hold `ct`; bytes 16..32 hold `tag`. The Nonce at bytes
12..16 is both an IV input and a wire-visible value.

Without `master_key`, the 32-byte field is computationally
indistinguishable from uniform random bytes, which is what real Chrome
emits in `legacy_session_id`.

### 3.2 Server state machine

```
                        packet on UDP/443
                              |
                              v
                  +-----------------------+
                  | parse QUIC long header|
                  +-----------------------+
                              |
                       Initial packet?
                       no |        | yes
                          v        v
                  forward to    +------------------------+
                  existing      | extract WindowID at    |
                  QUIC conn     | fixed offset in CH     |
                                +------------------------+
                                              |
                            WindowID in {t-1, t, t+1}?
                                no  |     | yes
                                    v     v
                              drop  +-----------------------+
                                    | derive window_key(W)  |
                                    | AES-GCM verify tag    |
                                    +-----------------------+
                                              |
                                    tag valid?
                                    no |    | yes
                                       v    v
                                  forward  +-----------------------+
                                  to real  | UserAuthenticator     |
                                  CDN      |  .Verify(shortID)     |
                                  (sec 4)  +-----------------------+
                                                       |
                                              ErrUnknownUser | ok
                                                            v
                                                       install user
                                                       session, run
                                                       L2 sliding-window
                                                       check, hand to
                                                       QUIC layer
```

### 3.3 Client handshake

The client MUST:

1. Build the ClientHello via uTLS so the byte layout matches a recent
   Chrome stable HTTP/3 ClientHello, with the `legacy_session_id`
   field replaced per section 3.1.
2. Set the SNI to a value drawn from the configured target pool.
3. Use ALPN `h3` and the QUIC version of the targeted Chrome release.
4. Use a Source Connection Id of the length used by that Chrome
   release (commonly 8 bytes).

Bytes other than `legacy_session_id` MUST round-trip through the
server to the real CDN unchanged.

### 3.4 Transport parameters

Both peers SHOULD emit QUIC v1 transport parameters whose values match
the targeted Chrome HTTP/3 release. The reference profile in
`behavior.Default()` is:

| Parameter                           | Value         |
| ----------------------------------- | ------------- |
| `max_idle_timeout`                  | 30 000 ms     |
| `handshake_idle_timeout` (server)   | 10 000 ms     |
| `max_udp_payload_size`              | 1452          |
| `initial_max_data`                  | 15 MiB        |
| `initial_max_stream_data_bidi_local`  | 6 MiB       |
| `initial_max_stream_data_bidi_remote` | 6 MiB       |
| `initial_max_stream_data_uni`       | 6 MiB         |
| `initial_max_streams_bidi`          | 100           |
| `initial_max_streams_uni`           | 100           |
| `ack_delay_exponent`                | 3             |
| `max_ack_delay`                     | 25 ms         |
| `active_connection_id_limit`        | 8             |
| `disable_active_migration`          | absent (false)|

The client populates its parameters via
`behavior.ApplyToTransportParameters`. The server applies the same
profile to its `quic-go` `Config` via `behavior.ApplyToQUICConfig`,
which only fills fields the operator left at zero so explicit
overrides survive. Additionally the server sets
`InitialPacketSize = 1252` to match Chrome's initial PMTU.

Connection migration MUST NOT be disabled: real Chrome leaves
`disable_active_migration` absent, so emitting it would form a
distinguishable transport-parameter fingerprint.

## 4. Transparent Forwarding

Packets that fail any check in section 3.2 are forwarded to a real
CDN endpoint resolved via `adapter.SNITargetProvider.ResolveRealTarget`.
The forwarder is a stateless 4-tuple UDP relay:

```
(probe_src_ip, probe_src_port) -> (target_addr, egress_port, last_seen)
```

Properties:

- Each entry is roughly 64 bytes; entries expire after 60 s of idle.
- QUIC packets are forwarded byte-for-byte with all CIDs preserved.
  RFC 9001 section 5.2 derives initial keys from the destination CID,
  so the real CDN performs the same key derivation the prober expects.
- No QUIC, TLS, or cryptographic state is allocated for forwarded
  flows. Per-packet cost is one map lookup plus one `sendto(2)`.

If `ResolveRealTarget` returns `ErrNoSNITarget`, the packet is dropped.

## 5. Anti-Replay

### 5.1 L0 (XDP, optional)

Implementations MAY install an XDP program on the listening NIC that
extracts the 4-byte WindowID from the QUIC Initial packet and drops
packets whose WindowID is not in `{t-1, t, t+1}`. L0 is optional and
does not affect correctness.

### 5.2 L1 - time-window key

The server pre-computes `window_key(t-1)`, `window_key(t)`, and
`window_key(t+1)` and rotates them once per `WindowSeconds`. Short-id
verification MUST succeed under one of these three keys; otherwise the
packet is dropped.

Cost is one AES-128 block plus one GCM tag verification per candidate
window.

### 5.3 L2 - sliding window

After L1 succeeds, the server checks a per-user 64-bit sliding window
keyed by `(UserID, WindowID)`:

- A 32-bit `Counter` is part of the inner payload. **TBD**: place
  it in the first 4 bytes of each stream's first DATA frame.
- The server tracks the highest `Counter` seen and a 64-bit bitmap
  for the previous 64 counters.
- `Counter <= highest - 64` is rejected (too old).
- Within the window, a set bit means a replay; reject.
- Otherwise, set the bit and accept.

## 6. Data Plane Constraints

| Property            | Value                                          |
| ------------------- | ---------------------------------------------- |
| Congestion control  | Standard BBRv2 only                            |
| PING interval       | Match targeted Chrome release (~30 s)          |
| PMTU schedule       | Match targeted Chrome release                  |
| ACK delay           | Match targeted Chrome release                  |
| Packet size mix     | Sample from Chrome release's empirical CDF     |
| SNI per connection  | Constant for the connection's lifetime         |
| SNI across conns    | MAY rotate from the configured pool            |

Aggressive congestion controllers (Brutal, BBR with constant pacing)
MUST NOT be used: their flat-rate signature is the largest data-plane
fingerprint that has burned previous-generation proxies.

A reference set of constants per Chrome release lives in package
`behavior`.

## 7. Control Stream

The first server-initiated bidirectional stream (QUIC stream id `0x01`)
is the **control stream**. The server opens it lazily, immediately
after the handshake completes, and uses it to push protocol-level
control frames to the client. Application data MUST NOT be carried on
this stream.

### 7.1 Frame layout

Every control frame is

```
+--------+----------+--------------------+
| Type 1 | Length 2 | Body (Length bytes)|
+--------+----------+--------------------+
```

`Type` and `Length` are big-endian. `Length` is bounded by
`proto.MaxFrameBodyLen` (currently 65 535). Receivers MUST silently
ignore unknown `Type` values so that minor-version additions do not
break existing peers.

### 7.2 Defined frame types

| Type | Name                          | Body                          |
| ---- | ----------------------------- | ----------------------------- |
| 0x01 | `ConnectionRecycleHint`       | `HandoffWindowMillis` u16 BE  |

## 8. Connection Recycling

At handshake completion the server samples per-connection thresholds:

```
deadline_age   = uniform(MinAge,   MaxAge)     // default 90..180 min
deadline_bytes = uniform(MinBytes, MaxBytes)   // default 3..8 GiB
```

When either threshold is crossed the server sends a
`ConnectionRecycleHint` frame on the control stream (section 7) with a
suggested handoff window (default 30 000 ms, encoded as the unsigned
big-endian millisecond value in the body). At most one hint is sent
per connection.

The client (`client.Pool`) then runs a three-stage handoff:

1. **Dial.** Open a fresh mirage connection in parallel, optionally
   with a different SNI from the configured pool.
2. **Promote.** Atomically swap the new connection in as "active" so
   that subsequent `OpenStream` calls land on it. Streams already
   running on the old connection continue undisturbed.
3. **Drain & close.** Park the old connection for
   `min(HandoffWindowMillis, DrainGrace)`. When the grace timer
   fires, issue `CONNECTION_CLOSE` on the old connection regardless of
   any remaining in-flight traffic.

Per-user state is keyed by `adapter.UserID`, so it survives rotation.

If the client has not registered an `OnRecycleHint` callback the
control stream is still accepted but the body is discarded — backwards
compatibility for clients that do not yet implement pooling.

## 9. Application Framing (Proxy)

The reference TCP proxy in package `proxy` carries a length-prefixed
request/response on each mirage stream. The format is:

```
client --> server   ProxyRequest  : Type 1 | Length 2 | Body
server --> client   ProxyResponse : Status 1 | Length 2 | Body
```

Body of `ProxyRequest` is `host \0 port_be16` (UTF-8 host, no NUL in
the host segment). The server returns `Status = 0` on success and
streams the upstream TCP data after the response header. Non-zero
status values are reserved.

### 9.1 Stream error codes

Both peers MAY terminate a stream half via `STOP_SENDING` (frame type
`0x05`) and `RESET_STREAM` (frame type `0x04`). The application error
code carried in those frames is a `uint64`. The proxy uses the
following codes:

| Code  | Meaning                                              |
| ----- | ---------------------------------------------------- |
| 0x10  | `ProxyErrIdleTimeout` — server-side idle watchdog    |

Other codes are reserved. Receivers MUST treat unknown codes as
opaque and surface them through `client.StreamError`.

## 10. Master Key Rotation

The server holds a **master key set** consisting of one *primary* key
plus zero or more *additional* keys. Window-key derivation
(section 2) is performed independently for every key in the set, and
short-id verification (section 5.2) accepts a packet if any of the
derived AEAD instances authenticates it.

Operators rotate keys with a make-before-break sequence:

1. **Stage.** Distribute a new key out of band; deploy it as an
   *additional* key while the existing primary remains active.
2. **Promote.** Call `Server.RotateMasterKeys(new, old)`, swapping the
   roles atomically. Old sessions continue to verify under `old`;
   newly handshaking clients use `new`.
3. **Retire.** After the longest configured `MaxAge` plus the recycle
   handoff window has elapsed, call
   `Server.RotateMasterKeys(new)` to drop the old key entirely.

`RotateMasterKeys` is safe to call at any time and never tears down an
established QUIC connection: it only swaps the dispatcher's verifier.

## 11. Security Considerations

In scope:

- Static fingerprinting of TLS / QUIC bytes.
- Active probing.
- Statistical / ML classification of encrypted flows.
- Replay attacks.

Out of scope:

- Master-key extraction from a compromised server.
- Global passive correlation across multiple vantage points.
- Adversary-controlled real CDN target.
- Side-channel attacks against AES-GCM.

Notes:

- Static fingerprinting: the wire bytes are produced by uTLS to match
  Chrome HTTP/3. Mirage-specific bytes (`legacy_session_id`, the
  encrypted control stream) are AEAD ciphertext.
- Active probing: a probe that does not encode a valid short-id is
  forwarded to the real CDN; it cannot tell the IP is anything other
  than a CDN endpoint.
- Statistical classification: data-plane constraints in section 6 and
  connection recycling in section 7 reduce the residual proxy
  signature; mirage does not claim undetectability under deep ML.
- Replay: L1 rejects stale-window packets at near-zero cost; L2 rejects
  precise replays inside the current window.

## 12. Versioning

- `proto.ProtocolVersion` is `mirage/0.1`. It is mixed into HKDF
  context but never sent on the wire.
- Backwards-incompatible changes bump the second component.
- New control-stream frame types may be added within a minor version;
  receivers MUST silently ignore unknown types.

## 13. Open Questions

1. Exact location of the `Counter` field used by L2.
2. How the client signals which `behavior` profile it targets.
3. Capability negotiation slot for new frame types within one version.
4. Datagram (RFC 9221) support and disguise as HTTP/3 datagrams.
5. Real-world calibration of `MinAge`, `MaxAge`, `MinBytes`, `MaxBytes`.
