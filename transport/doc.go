// Package transport holds the server-side helpers for parsing and
// decrypting QUIC long-header Initial packets: HKDF-derived initial
// keys, ClientHello reassembly from CRYPTO frames, and varint helpers
// shared with the dispatcher.
package transport
