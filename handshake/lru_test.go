package handshake

import "testing"

func TestSessionLRUPutGet(t *testing.T) {
	l := newSessionLRU(2)
	a := &SessionState{Decision: DispatchAuth}
	b := &SessionState{Decision: DispatchRelay}

	if ev := l.Put("a", a); ev != nil {
		t.Fatalf("unexpected eviction: %v", ev)
	}
	if ev := l.Put("b", b); ev != nil {
		t.Fatalf("unexpected eviction: %v", ev)
	}
	if got, ok := l.Get("a", true); !ok || got != a {
		t.Fatalf("Get(a)=%v,%v", got, ok)
	}
	if got, ok := l.Get("b", false); !ok || got != b {
		t.Fatalf("Get(b)=%v,%v", got, ok)
	}
}

func TestSessionLRUEvictsLeastRecentlyUsed(t *testing.T) {
	l := newSessionLRU(2)
	a := &SessionState{Decision: DispatchAuth}
	b := &SessionState{Decision: DispatchRelay}
	c := &SessionState{Decision: DispatchDrop}

	l.Put("a", a)
	l.Put("b", b)
	if _, ok := l.Get("a", true); !ok {
		t.Fatal("a missing after seed")
	}
	ev := l.Put("c", c)
	if ev != b {
		t.Fatalf("evicted=%v want b (%v)", ev, b)
	}
	if _, ok := l.Get("b", false); ok {
		t.Fatal("b should be gone")
	}
	if l.Len() != 2 {
		t.Fatalf("Len=%d want 2", l.Len())
	}
}

func TestSessionLRUDelete(t *testing.T) {
	l := newSessionLRU(4)
	l.Put("a", &SessionState{})
	if !l.Delete("a") {
		t.Fatal("Delete(a) reported missing")
	}
	if l.Delete("a") {
		t.Fatal("second Delete should report missing")
	}
	if l.Len() != 0 {
		t.Fatalf("Len=%d want 0", l.Len())
	}
}

func TestSessionLRUOverwriteSameKey(t *testing.T) {
	l := newSessionLRU(2)
	a1 := &SessionState{Decision: DispatchAuth}
	a2 := &SessionState{Decision: DispatchRelay}
	l.Put("a", a1)
	if ev := l.Put("a", a2); ev != nil {
		t.Fatalf("unexpected eviction on overwrite: %v", ev)
	}
	got, ok := l.Get("a", false)
	if !ok || got != a2 {
		t.Fatalf("Get returned %v,%v want a2", got, ok)
	}
	if l.Len() != 1 {
		t.Fatalf("Len=%d want 1", l.Len())
	}
}
