# mirage Threat Model

This document enumerates the adversaries mirage is designed to resist,
the assumptions under which those defences hold, and the failure modes
operators must accept. It is the companion to `spec.md` (what the
protocol does on the wire) and `operations.md` (how to run it).

The goal is not "perfect anonymity" — that is not achievable for a
single-node UDP service. The goal is that an adversary who can observe
and inject around an unmodified Chrome-talking-to-CDN baseline cannot
distinguish a mirage server from that baseline, cannot replay captured
handshakes into a working session, and cannot flood the server into
discarding legitimate traffic.

## 1. Adversary capabilities

We model three capability tiers; defences are stated against the
strongest tier that still leaves the property intact.

### A. Passive on-path observer
- Sees every packet, including timing and size.
- Cannot inject, drop, or modify.
- Cannot decrypt TLS or QUIC payloads.
- Has access to public information: TLS fingerprints of major browsers,
  ALPN values, IP reputation feeds, TLS certificate transparency logs.

### B. Active on-path attacker
- All of A, plus may drop, delay, modify, or inject packets.
- May initiate connections to the mirage server from arbitrary source
  IPs and ASNs.
- May replay previously captured packets verbatim or with mutations.

### C. Endpoint compromise
- Has temporary code execution on the mirage server (post-exploitation
  scenario), but no access to long-term offline secrets.
- Out of scope for confidentiality of past traffic; in scope for
  forward-secrecy reasoning around master-key rotation.

We explicitly do *not* model:
- Adversaries with access to the master key (game over by definition).
- Adversaries who can compromise the operator's CA (mirage's TLS is no
  stronger than its certificate chain).
- Traffic-correlation adversaries with a global passive view of both
  ends — single-hop tunnelling cannot defeat that and we do not pretend
  otherwise.

## 2. Properties claimed

### P1. Indistinguishability from a Chrome H3 baseline (vs. A)
The on-wire bytes — packet sizes, ALPN, TLS extensions, QUIC transport
parameters, GREASE patterns, congestion-control behaviour — match an
unmodified Chrome connection to a major CDN.

**Mechanism**
- TLS ClientHello / ServerHello use the same cipher list, extension
  order, and GREASE values as Chrome stable (see `behavior/chrome_h3.go`).
- Initial datagram padding is sampled from the Chrome-baseline
  distribution (`behavior.PadderPolicy`).
- Congestion control uses BBRv2 with the same limits Chrome ships
  (`congestion/bbr2`).
- The destination connection ID is rotated periodically (default 5 min,
  see `behavior.ChromeH3.CIDRotateInterval`) so long-lived flows do not
  expose a unique identifier across NAT rebinding events.

**Residual risk** Operators must keep the binary in step with the
current Chrome stable channel; a stale fingerprint becomes a unique
fingerprint within months. See `operations.md` §"Fingerprint refresh".

### P2. Active-probe deflection (vs. B)
An attacker who sends ClientHellos directly to the mirage UDP port
without a valid short-id receives a response indistinguishable from
the configured SNI relay target.

**Mechanism**
- The dispatcher decrypts the short-id with the L1 window key. On
  failure, the entire flow (Initial + subsequent datagrams) is bridged
  to the matching `[[sni_target]]` over plain TCP/UDP. The prober sees
  the real CDN's certificate and TLS Finished.
- The bridging happens at packet granularity inside
  `handshake.Server.transparentRelay`; mirage never injects its own
  data into the relayed stream.

**Residual risk** If the SNI relay pool is misconfigured (no entry for
the SNI the prober claimed), the connection is dropped — and a dropped
flow on UDP/443 is itself a fingerprint. Operators MUST configure at
least one `[[sni_target]]` matching every plausible SNI that resolves
to their server's IPs.

### P3. Replay resistance (vs. B)
Replaying a captured Initial datagram, in whole or in part, MUST NOT
produce a working session, even within the L1 window's validity period.

**Mechanism**
- Each accepted short-id is recorded in a sliding-window deduplication
  set (`replay.SlidingDedupe`) keyed by `(WindowID, ShortID, Nonce)`.
  The set retains entries for `2 * WindowSeconds` to cover clock skew
  on either side.
- Window keys derived from previous `master_key` epochs remain valid
  only as long as the operator keeps them in `additional_master_keys`.

**Residual risk** A successful replay before the deduper sees the
original would briefly produce two flows authenticating with the same
short-id; the second observes a duplicate-short-id error and is
dropped. The window of opportunity is bounded by the inter-packet
latency between attacker and server, in practice <100 ms.

### P4. Per-source rate limiting (vs. B)
A single source IP cannot exhaust the server by spraying invalid
Initials, because the Initial-decryption path is gated by a
token-bucket per `/24` (IPv4) or `/64` (IPv6) prefix.

**Mechanism**
- `handshake.Dispatcher.limiter` (configured via `RateLimit` in
  `mirage.toml`) issues `initial_per_sec` tokens per source prefix
  with `burst` capacity. Tokens are consumed before AES-GCM is run
  on a candidate Initial.
- Rate-limited datagrams are silently bridged to the SNI relay rather
  than dropped, so the attacker cannot distinguish a rate-limited
  prefix from one that is simply unauthenticated.

**Residual risk** A coordinated botnet with many distinct prefixes
defeats the per-prefix bucket. Operators MUST front mirage with a
network-edge rate limiter (cloud provider WAF, eBPF) sized to their
expected legitimate Initial rate.

### P5. Connection-ID unlinkability (vs. A)
After the handshake, an observer cannot trivially correlate a long-
lived mirage flow across NAT rebinding events using the destination
connection ID alone.

**Mechanism**
- The server issues fresh connection IDs via `NEW_CONNECTION_ID`.
- The client keeps an active pool (`client/cidpool.go`) and rotates the
  active DCID periodically, retiring the old sequence numbers via
  `RETIRE_CONNECTION_ID`.

**Residual risk** Source IP and port-range reuse remain stable
identifiers; CID rotation alone does not defeat netflow correlation.

## 3. Cryptographic agility & key hygiene

- `master_key` is rotated by adding a new key as the primary and
  keeping the old one in `additional_master_keys` for at least
  `2 * WindowSeconds`. The keyring is swap-atomic
  (`handshake.Server.RotateMasterKeys`).
- Window keys are ephemeral: a compromise of a single window key
  leaks at most `WindowSeconds` of accepted short-ids and never the
  master key itself (HKDF is a one-way derivation).
- TLS keys live on disk; their compromise breaks P2 (probes can
  detect the wrong certificate). Operators SHOULD use short-lived
  certificates from an automated issuer.

## 4. Operational invariants the operator MUST preserve

| # | Invariant                                                                      | Why                                |
|---|--------------------------------------------------------------------------------|------------------------------------|
| 1 | `master_key` and `tls_key` are stored mode-0600, owned by the mirage user.     | Disk-leak resistance.              |
| 2 | The host clock is synchronised within `WindowSeconds/2` (45 s by default).     | L1 window verification depends on it. |
| 3 | At least one `[[sni_target]]` matches every SNI advertised by the IP's PTR.    | P2 fallback indistinguishability.  |
| 4 | The binary is rebuilt within one Chrome stable cycle of upstream changes.      | P1 fingerprint freshness.          |
| 5 | `additional_master_keys` is non-empty during a rotation window.                | P3 replay resistance across rotation. |
| 6 | The UDP port is not also serving plain HTTP/3 traffic on the same IP.          | Avoids cross-protocol fingerprints. |

A breach of any invariant degrades the model from the listed property
to the property of the next-weaker tier (typically: mirage continues to
function as a working tunnel, but loses indistinguishability).

## 5. Out-of-scope items (deliberately)

- **Hiding that QUIC is being spoken at all.** mirage is camouflaged
  HTTP/3, not anti-DPI. Networks that block UDP/443 wholesale will
  block mirage too.
- **Cover traffic.** mirage does not generate fake traffic to mask
  silence on a flow. Workload-shape leakage is the user's problem.
- **Anonymity vs. the destination.** The proxy target sees the source
  IP of the mirage server; this is not Tor.
- **Multi-hop chaining.** A future version may chain mirage servers,
  but the current threat model assumes a single hop.
