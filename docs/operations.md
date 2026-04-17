# mirage Operations Guide

This document is the runbook for operators of a mirage server. It
covers installation, configuration, deployment, key rotation,
monitoring, and incident response. It does *not* repeat the protocol
specification (`spec.md`) or the threat model (`threat-model.md`); read
those first if you need to understand *why* a step exists.

## 1. Build & install

mirage is a single static Go binary. Cross-compile from any platform:

```bash
GOOS=linux GOARCH=amd64 go build -o mirage-server \
    ./examples/minimal-server
```

For production we recommend stripping symbols and disabling DWARF:

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w' \
    -o mirage-server ./examples/minimal-server
```

Place the binary at `/usr/local/bin/mirage-server` and chmod 0755.

### Required Linux kernel features
- `CAP_NET_BIND_SERVICE` (or run as root) to bind UDP/443.
- A kernel with `SO_REUSEPORT` for multi-process scaleout (optional).
- No iptables rules consuming ICMP unreachables for UDP/443; mirage
  needs them for path-MTU discovery.

## 2. Configuration

mirage reads a single TOML file (see
`examples/minimal-server/mirage.example.toml`). Copy it to
`/etc/mirage/mirage.toml`, edit, and chmod 0600 (the file embeds
`master_key`).

Mandatory keys:

| Key          | Purpose                                                |
|--------------|--------------------------------------------------------|
| `listen`     | UDP `host:port`. Use `0.0.0.0:443` for default deploy. |
| `master_key` | 64 hex chars (32 bytes). Generate with `openssl rand -hex 32`. |
| `tls_cert`   | PEM file, ECDSA P-256 or RSA 2048+, with full chain.   |
| `tls_key`    | PEM key matching `tls_cert`. Mode 0600.                |
| `[[user]]`   | At least one user table row.                           |

Recommended:

| Key                    | Purpose                                           |
|------------------------|---------------------------------------------------|
| `[[sni_target]]`       | Relay pool for active-probe deflection.           |
| `[rate_limit]`         | Per-source-prefix Initial bucket.                 |
| `[recycle]`            | Per-connection rotation thresholds.               |
| `additional_master_keys` | Non-empty during a key-rotation window.         |
| `session_ttl`          | Dispatcher 4-tuple cache TTL. Default 5 min.      |
| `drain`                | Shutdown grace period. Default 10 s.              |

For `master_key`, prefer `master_key_file = "/etc/mirage/mk.hex"` over
inlining the secret; the file form lets you keep the key in a separate
secrets-management mount.

## 3. systemd unit

```ini
# /etc/systemd/system/mirage.service
[Unit]
Description=mirage QUIC proxy
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/mirage-server -config /etc/mirage/mirage.toml
Restart=on-failure
RestartSec=2s
DynamicUser=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=
ReadOnlyPaths=/etc/mirage
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
```

Reload, enable, start:

```bash
systemctl daemon-reload
systemctl enable --now mirage.service
journalctl -u mirage -f
```

The binary logs structured slog records to stderr; capture them via
`journalctl -o json` for ingestion into Loki/Elasticsearch.

## 4. TLS certificate

Use a valid CA-issued certificate. Self-signed or invalid certs break
P2 (probe deflection) because the relayed CDN's cert chain looks
nothing like a self-signed one.

For automated issuance, configure your ACME client to write to
`/etc/mirage/cert.pem` and `/etc/mirage/key.pem` and to invoke
`systemctl reload mirage` after renewal. mirage SIGHUP support is
planned; until then, reload triggers a clean restart on the systemd
unit above.

## 5. Master-key rotation

Goal: replace `master_key` without dropping any in-flight or
short-window-replay-protected sessions.

1. Generate the new key:
   `openssl rand -hex 32 > /etc/mirage/mk-new.hex`
2. Edit `mirage.toml`:
   ```toml
   master_key            = "<contents of mk-new.hex>"
   additional_master_keys = ["<previous master_key>"]
   ```
3. `systemctl reload mirage` (or restart). The dispatcher accepts
   short-ids derived from either key.
4. Wait at least `2 * WindowSeconds` (default: 180 s) so all in-flight
   handshakes finish under the new key.
5. Distribute the new key to clients (out of band — the only secret
   they need).
6. After every client has rolled, remove the old key from
   `additional_master_keys` and reload again.

Failure modes:
- Forgetting step 4 strands existing clients: they continue to send
  short-ids derived from the old key and get bridged to the SNI relay.
  Symptom: spike in `dispatcher.unauthenticated_relayed`.
- Forgetting step 6 indefinitely is harmless for confidentiality but
  enlarges the replay-window surface; clean it up.

## 6. Monitoring

The server exposes counters and gauges via the `metrics.Sink`
abstraction (`metrics` package). Wire it to Prometheus by implementing
the sink in your binary; see `examples/` for the discard sink used by
`minimal-server`.

Indicators to alert on:

| Signal                                  | Meaning                                   | Action                                       |
|-----------------------------------------|-------------------------------------------|----------------------------------------------|
| `server.live_connections`               | Currently authenticated flows.            | Capacity planning.                           |
| `server.accept_fail` rate spike         | TLS handshakes failing post-auth.         | Cert misconfiguration; re-issue.             |
| `dispatcher.rate_limited` rate spike    | Per-prefix limiter saturating.            | Investigate source ASN; raise limit if benign. |
| `dispatcher.replay_dropped` >0 sustained | Active replay attempts.                   | Inspect source IPs; consider edge ACL.       |
| `dispatcher.unauthenticated_relayed`    | Probes / unknown short-ids.               | Baseline; spikes suggest scanning.           |
| `udp_proxy.live`                        | Active UDP-associate streams.             | Capacity / leak detection.                   |
| `udp_proxy.drop_authz`                  | UDP packets denied by authorizer.         | Misbehaving client or policy mismatch.       |

Recommended SLO: `dispatcher.replay_dropped == 0` over a 24 h window
when no rotation is in flight. A non-zero value is a security event,
not a perf event.

## 7. Drain & shutdown

`mirage-server` traps SIGINT and SIGTERM. On signal it:

1. Stops accepting new connections immediately.
2. Calls `handshake.Server.Drain(ctx)` with the configured `drain`
   timeout, sending CONNECTION_CLOSE on flows that did not finish in
   time.
3. Closes the underlying UDP socket.

Set `drain` generously (`30s`+) on busy nodes; impatient termination
manifests on the client as `INTERNAL_ERROR` instead of a clean close.

For zero-downtime restarts, run two systemd units on different ports
behind a load balancer that supports UDP weight steering. mirage does
not yet support socket handoff between processes; plan for the LB to
do the work.

## 8. Incident response

### 8.1 Suspected master-key compromise
1. Generate two fresh keys offline.
2. Stage the first as `master_key`, the second in
   `additional_master_keys`, and remove the suspected key entirely.
3. Reload. Existing flows derived from the compromised key fail
   authentication and bridge to the SNI relay.
4. Audit `dispatcher.replay_dropped` and access logs from the
   reload moment forward; any non-zero value indicates the attacker
   is still trying.
5. Rotate clients to the new `master_key` out of band.

### 8.2 Suspected SNI-relay misconfiguration
Symptom: probes hitting the IP receive RST or timeout instead of a
real CDN response.

1. Run `dig +short ANY <ip>` against your IP's PTRs to enumerate the
   plausible SNIs an attacker would try.
2. Ensure each one has a `[[sni_target]]` entry pointing to the
   matching real CDN endpoint.
3. Reload.

### 8.3 Resource exhaustion under attack
1. Tighten `[rate_limit]`: drop `initial_per_sec` to the floor of
   legitimate traffic, drop `burst` to small values (10–50).
2. Push the offender's prefix into a network-edge drop ACL; mirage's
   per-prefix limiter is a backstop, not a frontline.
3. Increase `auth_queue_depth` only if `dispatcher.queue_overflow`
   counter is non-zero — otherwise raising it just delays loss.

## 9. Upgrade procedure

mirage uses semantic versioning starting at `1.0.0`. Within a major
version:

- Patch upgrades (`1.x.y → 1.x.z`) are drop-in: stop, replace binary,
  start.
- Minor upgrades (`1.x → 1.y`) are drop-in unless the release notes
  specify a config migration step. Always read the release notes.

Across major versions:

1. Stage the new binary on a single canary node behind your LB.
2. Watch the canary's metrics for a full traffic cycle (≥ 24 h).
3. Roll out by replacing nodes one at a time, never more than 25 % of
   the fleet in flight. mirage clients tolerate connection loss; the
   blast radius of a bad upgrade is bounded by the LB's failover.

## 10. Backup & disaster recovery

- Treat `master_key`, `additional_master_keys`, and `tls_key` as the
  only stateful secrets. Back them up encrypted, off-host. Everything
  else (`mirage.toml` shape, `[[user]]` table) is config and lives in
  your normal config-management pipeline.
- A node loss with intact backups recovers by re-deploying the binary,
  restoring `/etc/mirage/`, and starting the systemd unit.
- There is no on-disk session state; nothing else to replicate or
  migrate.
