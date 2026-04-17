// Package client implements a minimal QUIC v1 client driven by a uTLS
// TLS state machine. It exists to support mirage's protocol semantics
// (Chrome HTTP/3 ClientHello fingerprint with a custom 32-byte
// legacy_session_id) on the client side, where upstream quic-go does
// not expose a hook to swap its TLS implementation.
//
// The client is deliberately small. It speaks enough of RFC 9000 and
// RFC 9001 to complete a TLS 1.3 handshake, open a single bidirectional
// stream, exchange data, and close cleanly. It does not implement loss
// detection beyond the bare minimum required by the test environment,
// and it does not perform congestion control.
//
// Production use is restricted to networks where mirage is the only
// QUIC implementation between client and server; deployment beyond that
// requires the additional mechanisms that a full QUIC stack provides.
package client
