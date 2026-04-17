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
// A Keyring may carry multiple master keys: at most one "primary" plus
// any number of secondary keys. The primary is the only one used to
// authenticate new sessions a server-driven flow would mint; secondary
// keys are accepted on Verify so that operators can rotate the primary
// key without forcing existing clients off the previous one. RotateKeys
// updates the set atomically.
//
// A Keyring is safe for concurrent use. Verify is wait-free in the
// common case; key rotation only happens when the wall clock crosses a
// window boundary or when RotateKeys is called.
type Keyring struct {
	now func() time.Time

	mu sync.RWMutex
	// masterKey is the primary key (the one a server would emit
	// secrets under, if it ever needed to). Kept addressable so
	// existing tests that probe k.masterKey continue to work.
	masterKey []byte
	// extraKeys are accepted-but-not-emitted master keys. They
	// occupy index 1..N in the per-window AEAD slice.
	extraKeys [][]byte
	cur       uint32
	// aeads[wid] is the per-master-key AEAD list for window wid.
	// Index 0 is the primary key; indexes 1..N follow extraKeys.
	aeads map[uint32][]cipher.AEAD
}

// NewKeyring returns a Keyring whose primary master key is masterKey,
// which must be 32 bytes. The Keyring pre-derives the previous,
// current, and next window AEADs.
func NewKeyring(masterKey []byte) (*Keyring, error) {
	return NewKeyringSet(masterKey)
}

// NewKeyringSet returns a Keyring with primary as the active master
// key plus zero or more extras that Verify will also accept. Each key
// must be 32 bytes. NewKeyring(primary) is equivalent to
// NewKeyringSet(primary).
func NewKeyringSet(primary []byte, extras ...[]byte) (*Keyring, error) {
	if len(primary) != 32 {
		return nil, errors.New("mirage: master key must be 32 bytes")
	}
	for i, ek := range extras {
		if len(ek) != 32 {
			return nil, errors.New("mirage: extra master key #" + itoa(i) + " must be 32 bytes")
		}
	}
	k := &Keyring{
		now:       time.Now,
		masterKey: append([]byte(nil), primary...),
		extraKeys: cloneKeys(extras),
		aeads:     make(map[uint32][]cipher.AEAD, 3),
	}
	if err := k.refresh(replay.CurrentWindowID()); err != nil {
		return nil, err
	}
	return k, nil
}

// RotateKeys atomically swaps the master-key set. primary becomes the
// new active master key; extras are the secondary keys Verify will
// also accept. Existing AEADs are recomputed for all three live
// windows. Returns an error if any key is the wrong length.
//
// The typical rotation cadence is to call RotateKeys with
// (newKey, oldKey) at deploy time, then a few hours later call
// RotateKeys(newKey) once you're confident no client is still pinned
// to the old key.
func (k *Keyring) RotateKeys(primary []byte, extras ...[]byte) error {
	if len(primary) != 32 {
		return errors.New("mirage: master key must be 32 bytes")
	}
	for i, ek := range extras {
		if len(ek) != 32 {
			return errors.New("mirage: extra master key #" + itoa(i) + " must be 32 bytes")
		}
	}
	k.mu.Lock()
	k.masterKey = append([]byte(nil), primary...)
	k.extraKeys = cloneKeys(extras)
	k.aeads = make(map[uint32][]cipher.AEAD, 3)
	k.cur = 0
	k.mu.Unlock()
	return k.refresh(replay.WindowID(k.now()))
}

// Verify decrypts the 32-byte session_id field and returns the contained
// short-id on success. The reported windowID is the value that was used
// to authenticate the input. Verify tries each known master key for
// the indicated window in order (primary first); the first AEAD that
// authenticates wins.
//
// Verify returns ErrInvalidSessionID for any malformed input, unknown
// window, or AEAD failure.
func (k *Keyring) Verify(sessionID []byte) (shortID []byte, windowID uint32, err error) {
	if len(sessionID) != proto.SessionIDLen {
		return nil, 0, ErrInvalidSessionID
	}
	wid := binary.BigEndian.Uint32(sessionID[proto.SessionIDWindowOffset:])

	aeads := k.aeadsFor(wid)
	if len(aeads) == 0 {
		// Either far in the past, far in the future, or we have not yet
		// rotated through a window boundary. Try a refresh and look again.
		if err := k.refresh(replay.WindowID(k.now())); err != nil {
			return nil, 0, err
		}
		aeads = k.aeadsFor(wid)
		if len(aeads) == 0 {
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

	for _, aead := range aeads {
		if plain, openErr := aead.Open(nil, iv[:], sealed, aad); openErr == nil {
			return plain, wid, nil
		}
	}
	return nil, 0, ErrInvalidSessionID
}

func (k *Keyring) aeadsFor(wid uint32) []cipher.AEAD {
	k.mu.RLock()
	a := k.aeads[wid]
	k.mu.RUnlock()
	return a
}

func (k *Keyring) refresh(target uint32) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	expectedLen := 1 + len(k.extraKeys)
	if k.cur == target && len(k.aeads) == 3 {
		// Verify each window has the expected AEAD count; if RotateKeys
		// has changed the set, we still need to repopulate.
		ok := true
		for _, list := range k.aeads {
			if len(list) != expectedLen {
				ok = false
				break
			}
		}
		if ok {
			return nil
		}
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
	masters := make([][]byte, 0, expectedLen)
	masters = append(masters, k.masterKey)
	masters = append(masters, k.extraKeys...)
	for wid := range want {
		list, err := deriveAEADs(masters, wid)
		if err != nil {
			return err
		}
		k.aeads[wid] = list
	}
	k.cur = target
	return nil
}

func deriveAEADs(masters [][]byte, wid uint32) ([]cipher.AEAD, error) {
	out := make([]cipher.AEAD, 0, len(masters))
	for _, mk := range masters {
		key, err := replay.DeriveWindowKey(mk, wid)
		if err != nil {
			return nil, err
		}
		block, err := aes.NewCipher(key)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(block)
		if err != nil {
			return nil, err
		}
		out = append(out, aead)
	}
	return out, nil
}

func cloneKeys(in [][]byte) [][]byte {
	if len(in) == 0 {
		return nil
	}
	out := make([][]byte, len(in))
	for i, k := range in {
		out[i] = append([]byte(nil), k...)
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
