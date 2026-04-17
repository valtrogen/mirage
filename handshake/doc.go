// Package handshake implements the mirage handshake on top of QUIC.
//
// Server: parse incoming Initial packets, decrypt the short-id from
// legacy_session_id, dispatch to the local TLS terminator on success
// or to the 4-tuple UDP relay on failure.
//
// Client: build a Chrome HTTP/3 ClientHello with the encrypted
// short-id and start a normal QUIC handshake.
package handshake
