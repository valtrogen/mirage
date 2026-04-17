package handshake

import (
	"bytes"
	"testing"

	"github.com/valtrogen/mirage/proto"
)

// FuzzDecodeSessionID checks that DecodeSessionID never panics and
// always returns ErrInvalidSessionID for inputs that are not exactly
// proto.SessionIDLen bytes long. For correctly-sized inputs the
// decoder may return ErrInvalidSessionID, a real shortID, or any
// other error — but it must do so without crashing.
//
// Run as `go test -run=^$ -fuzz=FuzzDecodeSessionID ./handshake/...`.
func FuzzDecodeSessionID(f *testing.F) {
	key := bytes.Repeat([]byte{0x77}, 16)
	short := []byte("\x01\x02\x03\x04\x05\x06\x07\x08")

	// Seed: one valid encoding, plus a few truncated variants.
	enc := make([]byte, proto.SessionIDLen)
	if err := EncodeSessionID(enc, key, short, 1234); err != nil {
		f.Fatalf("seed encode: %v", err)
	}
	f.Add(enc)
	f.Add(enc[:proto.SessionIDLen-1])
	f.Add(append([]byte{}, enc...))
	f.Add([]byte{})
	f.Add(make([]byte, proto.SessionIDLen))

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _, _ = DecodeSessionID(data, key)
	})
}
