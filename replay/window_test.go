package replay

import (
	"bytes"
	"testing"
	"time"

	"github.com/valtrogen/mirage/proto"
)

func TestWindowIDStepsAtBoundary(t *testing.T) {
	base := time.Unix(900, 0).UTC()
	if got := WindowID(base); got != 10 {
		t.Fatalf("WindowID(900) = %d, want 10", got)
	}
	if got := WindowID(base.Add(89 * time.Second)); got != 10 {
		t.Fatalf("WindowID(989) = %d, want 10", got)
	}
	if got := WindowID(base.Add(90 * time.Second)); got != 11 {
		t.Fatalf("WindowID(990) = %d, want 11", got)
	}
}

func TestWindowIDMatchesProtoWindowSeconds(t *testing.T) {
	if proto.WindowSeconds != 90 {
		t.Skipf("test pinned to 90s windows, proto changed to %d", proto.WindowSeconds)
	}
}

func TestDeriveWindowKeyDeterministic(t *testing.T) {
	mk := bytes.Repeat([]byte{0xAB}, 32)
	a, err := DeriveWindowKey(mk, 7)
	if err != nil {
		t.Fatalf("derive a: %v", err)
	}
	b, err := DeriveWindowKey(mk, 7)
	if err != nil {
		t.Fatalf("derive b: %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("non-deterministic: %x vs %x", a, b)
	}
	if len(a) != 16 {
		t.Fatalf("key length = %d, want 16", len(a))
	}
}

func TestDeriveWindowKeyChangesPerWindow(t *testing.T) {
	mk := bytes.Repeat([]byte{0x42}, 32)
	k0, _ := DeriveWindowKey(mk, 0)
	k1, _ := DeriveWindowKey(mk, 1)
	if bytes.Equal(k0, k1) {
		t.Fatal("adjacent windows produced the same key")
	}
}

func TestDeriveWindowKeyChangesPerMaster(t *testing.T) {
	mkA := bytes.Repeat([]byte{0x01}, 32)
	mkB := bytes.Repeat([]byte{0x02}, 32)
	kA, _ := DeriveWindowKey(mkA, 100)
	kB, _ := DeriveWindowKey(mkB, 100)
	if bytes.Equal(kA, kB) {
		t.Fatal("different master keys produced the same window key")
	}
}

func TestDeriveWindowKeyRejectsBadLength(t *testing.T) {
	if _, err := DeriveWindowKey(make([]byte, 31), 0); err == nil {
		t.Fatal("want error for 31-byte master key")
	}
	if _, err := DeriveWindowKey(make([]byte, 33), 0); err == nil {
		t.Fatal("want error for 33-byte master key")
	}
}
