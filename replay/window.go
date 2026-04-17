package replay

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	"github.com/valtrogen/mirage/proto"
)

// WindowID returns the mirage window identifier for the given time, defined
// as the low 32 bits of floor(t.Unix() / proto.WindowSeconds).
func WindowID(t time.Time) uint32 {
	return uint32(t.Unix() / proto.WindowSeconds)
}

// CurrentWindowID returns WindowID(time.Now()).
func CurrentWindowID() uint32 {
	return WindowID(time.Now())
}

// DeriveWindowKey returns the 16-byte AES-128 key used to encrypt the
// short-id field for the given WindowID. masterKey must be 32 bytes.
//
// The derivation matches docs/spec.md section 2:
//
//	HKDF-Extract(salt = MasterKeySalt, ikm = masterKey)
//	HKDF-Expand(info = "mirage v1 window" || u64_be(windowID), L = 16)
func DeriveWindowKey(masterKey []byte, windowID uint32) ([]byte, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("mirage: master key must be 32 bytes")
	}

	var info [len("mirage v1 window") + 8]byte
	copy(info[:], "mirage v1 window")
	binary.BigEndian.PutUint64(info[len("mirage v1 window"):], uint64(windowID))

	return hkdf.Key(sha256.New, masterKey, []byte(proto.MasterKeySalt), string(info[:]), 16)
}
