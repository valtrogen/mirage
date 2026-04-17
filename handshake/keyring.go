package handshake

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"sync"
	"time"

	"github.com/valtrogen/mirage/proto"
	"github.com/valtrogen/mirage/replay"
)

// Keyring holds AEAD instances for the three active mirage time windows
// (previous, current, next) so the hot verification path never re-derives
// keys or reconstructs ciphers.
//
// A Keyring is safe for concurrent use. Verify is wait-free in the common
// case; key rotation only happens when the wall clock crosses a window
// boundary.
type Keyring struct {
	masterKey []byte

	now func() time.Time

	mu    sync.RWMutex
	cur   uint32
	aeads map[uint32]cipher.AEAD
}

// NewKeyring returns a Keyring backed by masterKey, which must be 32
// bytes. The Keyring pre-derives current, previous, and next window
// keys.
func NewKeyring(masterKey []byte) (*Keyring, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("mirage: master key must be 32 bytes")
	}
	k := &Keyring{
		masterKey: append([]byte(nil), masterKey...),
		now:       time.Now,
		aeads:     make(map[uint32]cipher.AEAD, 3),
	}
	if err := k.refresh(replay.CurrentWindowID()); err != nil {
		return nil, err
	}
	return k, nil
}

// Verify decrypts the 32-byte session_id field and returns the contained
// short-id on success. The reported windowID is the value that was used
// to authenticate the input.
//
// Verify returns ErrInvalidSessionID for any malformed input, unknown
// window, or AEAD failure.
func (k *Keyring) Verify(sessionID []byte) (shortID []byte, windowID uint32, err error) {
	if len(sessionID) != proto.SessionIDLen {
		return nil, 0, ErrInvalidSessionID
	}
	wid := binary.BigEndian.Uint32(sessionID[proto.SessionIDWindowOffset:])

	aead := k.aeadFor(wid)
	if aead == nil {
		// Either far in the past, far in the future, or we have not yet
		// rotated through a window boundary. Try a refresh and look again.
		if err := k.refresh(replay.WindowID(k.now())); err != nil {
			return nil, 0, err
		}
		aead = k.aeadFor(wid)
		if aead == nil {
			return nil, 0, ErrInvalidSessionID
		}
	}

	var iv [12]byte
	binary.BigEndian.PutUint32(iv[0:4], wid)
	copy(iv[4:8], sessionID[proto.SessionIDNonceOffset:proto.SessionIDNonceOffset+proto.SessionIDNonceLen])

	sealed := make([]byte, 0, proto.SessionIDShortIDLen+proto.SessionIDTagLen)
	sealed = append(sealed, sessionID[proto.SessionIDShortIDOffset:proto.SessionIDShortIDOffset+proto.SessionIDShortIDLen]...)
	sealed = append(sealed, sessionID[proto.SessionIDTagOffset:proto.SessionIDTagOffset+proto.SessionIDTagLen]...)
	aad := sessionID[proto.SessionIDWindowOffset : proto.SessionIDWindowOffset+proto.SessionIDWindowLen]

	plain, err := aead.Open(nil, iv[:], sealed, aad)
	if err != nil {
		return nil, 0, ErrInvalidSessionID
	}
	return plain, wid, nil
}

func (k *Keyring) aeadFor(wid uint32) cipher.AEAD {
	k.mu.RLock()
	a := k.aeads[wid]
	k.mu.RUnlock()
	return a
}

func (k *Keyring) refresh(target uint32) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.cur == target && len(k.aeads) == 3 {
		return nil
	}

	want := map[uint32]struct{}{
		target - 1: {},
		target:     {},
		target + 1: {},
	}

	for wid := range k.aeads {
		if _, keep := want[wid]; !keep {
			delete(k.aeads, wid)
		}
	}
	for wid := range want {
		if _, ok := k.aeads[wid]; ok {
			continue
		}
		key, err := replay.DeriveWindowKey(k.masterKey, wid)
		if err != nil {
			return err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return err
		}
		k.aeads[wid] = aead
	}
	k.cur = target
	return nil
}
