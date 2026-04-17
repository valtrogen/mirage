package handshake

import (
	"bytes"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/valtrogen/mirage/proto"
	"github.com/valtrogen/mirage/replay"
)

func newKeyringWithClock(t *testing.T, mk []byte, now time.Time) *Keyring {
	t.Helper()
	k, err := NewKeyring(mk)
	if err != nil {
		t.Fatalf("NewKeyring: %v", err)
	}
	k.now = func() time.Time { return now }
	if err := k.refresh(replay.WindowID(now)); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	return k
}

func encodeWithKeyring(t *testing.T, k *Keyring, shortID []byte, wid uint32) []byte {
	t.Helper()
	wkey, err := replay.DeriveWindowKey(k.masterKey, wid)
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	out := make([]byte, proto.SessionIDLen)
	if err := EncodeSessionID(out, wkey, shortID, wid); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return out
}

func TestKeyringVerifyCurrentWindow(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	now := time.Unix(1_700_000_000, 0)
	k := newKeyringWithClock(t, mk, now)

	wid := replay.WindowID(now)
	shortID := []byte("12345678")
	sid := encodeWithKeyring(t, k, shortID, wid)

	got, gotWID, err := k.Verify(sid)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if gotWID != wid {
		t.Fatalf("windowID = %d, want %d", gotWID, wid)
	}
	if !bytes.Equal(got, shortID) {
		t.Fatalf("shortID = %x, want %x", got, shortID)
	}
}

func TestKeyringVerifyAdjacentWindows(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	now := time.Unix(1_700_000_000, 0)
	k := newKeyringWithClock(t, mk, now)

	wid := replay.WindowID(now)
	shortID := []byte("ABCDEFGH")

	for _, w := range []uint32{wid - 1, wid, wid + 1} {
		sid := encodeWithKeyring(t, k, shortID, w)
		got, gotW, err := k.Verify(sid)
		if err != nil {
			t.Fatalf("window %d: Verify: %v", w, err)
		}
		if gotW != w || !bytes.Equal(got, shortID) {
			t.Fatalf("window %d: got (%x, %d)", w, got, gotW)
		}
	}
}

func TestKeyringRejectsFarWindows(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	now := time.Unix(1_700_000_000, 0)
	k := newKeyringWithClock(t, mk, now)

	wid := replay.WindowID(now)
	shortID := []byte("01234567")

	for _, w := range []uint32{wid - 100, wid + 100} {
		sid := encodeWithKeyring(t, k, shortID, w)
		if _, _, err := k.Verify(sid); err != ErrInvalidSessionID {
			t.Fatalf("window %d: want ErrInvalidSessionID, got %v", w, err)
		}
	}
}

func TestKeyringRefreshAfterClockAdvances(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	t0 := time.Unix(1_700_000_000, 0)
	k := newKeyringWithClock(t, mk, t0)

	// Advance clock by many windows so the next call must refresh.
	t1 := t0.Add(10 * time.Duration(proto.WindowSeconds) * time.Second)
	k.now = func() time.Time { return t1 }

	wid := replay.WindowID(t1)
	sid := encodeWithKeyring(t, k, []byte("aabbccdd"), wid)
	if _, gotW, err := k.Verify(sid); err != nil || gotW != wid {
		t.Fatalf("Verify after rotate: err=%v wid=%d want=%d", err, gotW, wid)
	}
}

func TestKeyringRejectsTamperedSessionID(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	now := time.Unix(1_700_000_000, 0)
	k := newKeyringWithClock(t, mk, now)

	sid := encodeWithKeyring(t, k, []byte("ZZZZZZZZ"), replay.WindowID(now))
	sid[20] ^= 0x80
	if _, _, err := k.Verify(sid); err != ErrInvalidSessionID {
		t.Fatalf("want ErrInvalidSessionID, got %v", err)
	}
}

func TestKeyringConcurrent(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	now := time.Unix(1_700_000_000, 0)
	k := newKeyringWithClock(t, mk, now)
	wid := replay.WindowID(now)
	sid := encodeWithKeyring(t, k, []byte("mnopqrst"), wid)

	const workers = 16
	const each = 1000
	var wg sync.WaitGroup
	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < each; j++ {
				if _, _, err := k.Verify(sid); err != nil {
					t.Errorf("Verify: %v", err)
					return
				}
			}
		}()
	}
	wg.Wait()
}

func TestKeyringSetAcceptsExtraKey(t *testing.T) {
	primary := make([]byte, 32)
	if _, err := rand.Read(primary); err != nil {
		t.Fatalf("rand primary: %v", err)
	}
	old := make([]byte, 32)
	if _, err := rand.Read(old); err != nil {
		t.Fatalf("rand old: %v", err)
	}
	k, err := NewKeyringSet(primary, old)
	if err != nil {
		t.Fatalf("NewKeyringSet: %v", err)
	}
	wid := replay.CurrentWindowID()
	// Encode a session id under the *old* key.
	wkeyOld, err := replay.DeriveWindowKey(old, wid)
	if err != nil {
		t.Fatalf("derive old: %v", err)
	}
	sid := make([]byte, proto.SessionIDLen)
	if err := EncodeSessionID(sid, wkeyOld, []byte("87654321"), wid); err != nil {
		t.Fatalf("encode: %v", err)
	}
	short, gotWid, err := k.Verify(sid)
	if err != nil {
		t.Fatalf("Verify(sid encoded under extra key): %v", err)
	}
	if gotWid != wid {
		t.Fatalf("wid mismatch: got %d want %d", gotWid, wid)
	}
	if !bytes.Equal(short, []byte("87654321")) {
		t.Fatalf("short %q", short)
	}
}

func TestKeyringRotateKeysSwapsPrimary(t *testing.T) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	rand.Read(a)
	rand.Read(b)
	k, err := NewKeyringSet(a)
	if err != nil {
		t.Fatalf("NewKeyringSet: %v", err)
	}
	if err := k.RotateKeys(b, a); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	wid := replay.CurrentWindowID()

	// New session encoded under the *new* primary must verify.
	wkeyNew, _ := replay.DeriveWindowKey(b, wid)
	sidNew := make([]byte, proto.SessionIDLen)
	if err := EncodeSessionID(sidNew, wkeyNew, []byte("87654321"), wid); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := k.Verify(sidNew); err != nil {
		t.Fatalf("verify new: %v", err)
	}
	// Old session encoded under the *previous* primary (now an extra)
	// must still verify.
	wkeyOld, _ := replay.DeriveWindowKey(a, wid)
	sidOld := make([]byte, proto.SessionIDLen)
	if err := EncodeSessionID(sidOld, wkeyOld, []byte("12345678"), wid); err != nil {
		t.Fatalf("encode old: %v", err)
	}
	if _, _, err := k.Verify(sidOld); err != nil {
		t.Fatalf("verify old after rotation: %v", err)
	}
}

func TestKeyringRotateKeysDropsRetiredKey(t *testing.T) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	rand.Read(a)
	rand.Read(b)
	k, err := NewKeyringSet(a)
	if err != nil {
		t.Fatalf("NewKeyringSet: %v", err)
	}
	if err := k.RotateKeys(b); err != nil {
		t.Fatalf("RotateKeys: %v", err)
	}
	wid := replay.CurrentWindowID()
	wkeyOld, _ := replay.DeriveWindowKey(a, wid)
	sid := make([]byte, proto.SessionIDLen)
	if err := EncodeSessionID(sid, wkeyOld, []byte("87654321"), wid); err != nil {
		t.Fatalf("encode: %v", err)
	}
	if _, _, err := k.Verify(sid); err == nil {
		t.Fatal("expected Verify to reject session under retired key")
	}
}

func TestKeyringRejectsBadMasterKey(t *testing.T) {
	if _, err := NewKeyring(make([]byte, 31)); err == nil {
		t.Fatal("want error for 31-byte master key")
	}
}
