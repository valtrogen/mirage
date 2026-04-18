# Mirage patch on top of refraction-networking/uquic

Upstream: https://github.com/refraction-networking/uquic @ v0.0.6

## Why this fork exists

Mirage's covert authentication channel is the TLS `legacy_session_id`
field. uTLS — which uquic uses to build the ClientHello — runs an
internal pass that zeros `legacy_session_id` whenever the connection
is in QUIC mode (RFC 9001 §8.4 forbids non-empty session IDs in QUIC
ClientHellos). Without a hook to re-inject the bytes after that pass,
the mirage server's dispatcher sees an empty `session_id`, fails to
authenticate the connection, and routes it to the SNI relay.

## Patch scope (3 files, ~5 lines)

1. `u_quic_spec.go`
   Adds an optional `PostApplyPreset func(*tls.UQUICConn) error` field
   on `QUICSpec`. Mirage installs a hook that re-stamps the encrypted
   short-id into the ClientHello.

2. `u_connection.go`
   Plumbs `uSpec.PostApplyPreset` into `handshake.NewUCryptoSetupClient`.

3. `internal/handshake/u_crypto_setup.go`
   Calls the hook (if non-nil) right after `ApplyPreset` and before
   `Start` on the embedded `tls.UQUICConn`.

   Also stubs out the `tls.QUICStoreSession` event handler to a
   no-op: upstream `*utls.UQUICConn` does not expose `StoreSession`
   under utls v1.8.0+, and mirage does not use 0-RTT resumption.

## Vendor contents

This tree contains the import closure required to build mirage:
the top-level `uquic` package plus `internal/`, `quicvarint/`, and
`logging/`. Subpackages, examples, integration tests, mocks, and
documentation that mirage does not link have been omitted.

## Upgrading

When re-syncing from upstream:

1. Drop a fresh upstream tree in place.
2. Re-apply the 3-file patch listed above.
3. Re-run `go build ./...` and `go test ./...` from the mirage module
   root; remove anything that does not appear in the import closure.

## Removing the fork

If upstream merges an equivalent hook, replace the `replace` directive
in `mirage/go.mod` with a regular `require` and delete `_vendor/uquic/`.
