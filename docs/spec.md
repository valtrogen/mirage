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

## 7. Connection Recycling

At handshake completion the server samples per-connection thresholds:

```
deadline_age   = uniform(MinAge,   MaxAge)     // default 90..180 min
deadline_bytes = uniform(MinBytes, MaxBytes)   // default 3..8 GiB
```

When either threshold is crossed, AND the BBR controller is in
ProbeRTT or a low-bandwidth state, the server sends a
`FrameTypeConnectionRecycleHint` with a suggested handoff window
(default 30 000 ms).

The client then:

1. Opens a new mirage connection in parallel, with a fresh SNI.
2. Routes new application streams to the new connection.
3. Lets in-flight streams on the old connection drain for up to
   `HandoffWindowMillis`.
4. Issues `CONNECTION_CLOSE` on the old connection once drained or
   the handoff window expires.

Per-user state is keyed by `adapter.UserID`, so it survives rotation.

## 8. Security Considerations

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

## 9. Versioning

- `proto.ProtocolVersion` is `mirage/0.1`. It is mixed into HKDF
  context but never sent on the wire.
- Backwards-incompatible changes bump the second component.
- New control-stream frame types may be added within a minor version;
  receivers MUST silently ignore unknown types.

## 10. Open Questions

1. Exact location of the `Counter` field used by L2.
2. How the client signals which `behavior` profile it targets.
3. Capability negotiation slot for new frame types within one version.
4. Datagram (RFC 9221) support and disguise as HTTP/3 datagrams.
5. Real-world calibration of `MinAge`, `MaxAge`, `MinBytes`, `MaxBytes`.
