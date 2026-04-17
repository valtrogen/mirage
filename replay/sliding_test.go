package replay

import (
	"sync"
	"testing"
)

func TestSlidingWindowAcceptsInOrder(t *testing.T) {
	w := NewSlidingWindow(64)
	for i := uint64(0); i < 10; i++ {
		if !w.Check(i) {
			t.Fatalf("seq %d rejected", i)
		}
	}
	if w.Last() != 9 {
		t.Fatalf("Last = %d, want 9", w.Last())
	}
}

func TestSlidingWindowRejectsExactDuplicate(t *testing.T) {
	w := NewSlidingWindow(64)
	if !w.Check(100) {
		t.Fatal("first 100 rejected")
	}
	if w.Check(100) {
		t.Fatal("duplicate 100 accepted")
	}
}

func TestSlidingWindowAcceptsOutOfOrderInsideWindow(t *testing.T) {
	w := NewSlidingWindow(64)
	w.Check(50)
	if !w.Check(48) {
		t.Fatal("out-of-order seq inside window rejected")
	}
	if w.Check(48) {
		t.Fatal("duplicate of out-of-order seq accepted")
	}
}

func TestSlidingWindowRejectsBeyondWindow(t *testing.T) {
	w := NewSlidingWindow(64)
	w.Check(200)
	// 200 - 64 = 136, anything <= 136 is too old
	if w.Check(136) {
		t.Fatal("seq exactly at width boundary should be rejected")
	}
	if w.Check(0) {
		t.Fatal("seq 0 should be rejected when last is 200")
	}
	if !w.Check(137) {
		t.Fatal("seq just inside window should be accepted")
	}
}

func TestSlidingWindowJumpAheadResets(t *testing.T) {
	w := NewSlidingWindow(64)
	w.Check(10)
	w.Check(11)
	if !w.Check(1000) {
		t.Fatal("large jump rejected")
	}
	// Old packet near 11 must now be too old.
	if w.Check(11) {
		t.Fatal("post-jump duplicate of 11 should be rejected")
	}
}

func TestSlidingWindowSeedAcceptsAnything(t *testing.T) {
	w := NewSlidingWindow(64)
	if !w.Check(1 << 40) {
		t.Fatal("first Check should accept any value")
	}
	if w.Check(1 << 40) {
		t.Fatal("immediate duplicate after seed must be rejected")
	}
}

func TestSlidingWindowSmallWidth(t *testing.T) {
	w := NewSlidingWindow(8)
	w.Check(20)
	if w.Check(12) {
		t.Fatal("seq 12 outside width-8 window should be rejected")
	}
	if !w.Check(13) {
		t.Fatal("seq 13 just inside width-8 window should be accepted")
	}
}

func TestSlidingWindowSnapshotEmpty(t *testing.T) {
	w := NewSlidingWindow(64)
	last, bm, seeded := w.Snapshot()
	if seeded || last != 0 || bm != 0 {
		t.Fatalf("empty snapshot: last=%d bm=%x seeded=%v", last, bm, seeded)
	}
}

func TestSlidingWindowSnapshotMatchesAccepted(t *testing.T) {
	w := NewSlidingWindow(64)
	for _, s := range []uint64{0, 1, 2, 4, 7} {
		if !w.Check(s) {
			t.Fatalf("Check(%d) rejected", s)
		}
	}
	last, bm, seeded := w.Snapshot()
	if !seeded {
		t.Fatal("snapshot reports !seeded after Check")
	}
	if last != 7 {
		t.Fatalf("last=%d want 7", last)
	}
	// Bits set: 0 (=7), 3 (=4), 5 (=2), 6 (=1), 7 (=0).
	wantBits := []uint{0, 3, 5, 6, 7}
	var want uint64
	for _, b := range wantBits {
		want |= uint64(1) << b
	}
	if bm != want {
		t.Fatalf("bm=%b want %b", bm, want)
	}
}

func TestSlidingWindowConcurrent(t *testing.T) {
	// Launch many goroutines sharing the same window. Each picks a
	// disjoint seq range so no duplicates exist; we only assert that no
	// accepted seq is dropped and no duplicate is reported.
	w := NewSlidingWindow(64)
	const workers = 8
	const perWorker = 10000
	var wg sync.WaitGroup
	wg.Add(workers)

	accepted := make([]int, workers)
	for k := 0; k < workers; k++ {
		go func(id int) {
			defer wg.Done()
			base := uint64(id*perWorker + 1)
			for i := uint64(0); i < perWorker; i++ {
				if w.Check(base + i) {
					accepted[id]++
				}
			}
		}(k)
	}
	wg.Wait()

	total := 0
	for _, n := range accepted {
		total += n
	}
	// Some interleaving will push older packets out of the window before
	// they get checked, so total can be < workers*perWorker. The hard
	// invariant is that no seq is double-accepted, which we check by
	// re-running every seq and asserting all are now refused.
	for k := 0; k < workers; k++ {
		base := uint64(k*perWorker + 1)
		for i := uint64(0); i < perWorker; i++ {
			if w.Check(base + i) {
				t.Fatalf("seq %d accepted twice", base+i)
			}
		}
	}
	if total == 0 {
		t.Fatal("no seq accepted; concurrency path is broken")
	}
}
