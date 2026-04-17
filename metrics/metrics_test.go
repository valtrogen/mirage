package metrics

import (
	"sync"
	"testing"
)

func TestDiscardSinkIsNoOp(t *testing.T) {
	c := Discard.Counter("anything")
	c.Add(7)
	if c.Value() != 0 {
		t.Fatalf("Discard counter retained value: %d", c.Value())
	}
	g := Discard.Gauge("anything")
	g.Set(42)
	if g.Value() != 0 {
		t.Fatalf("Discard gauge retained value: %d", g.Value())
	}
	Discard.Histogram("anything").Observe(1.0)
}

func TestMemorySinkSameNameSameInstrument(t *testing.T) {
	s := NewMemorySink()
	a := s.Counter("hits")
	b := s.Counter("hits")
	a.Add(3)
	b.Add(4)
	if got := s.CounterValue("hits"); got != 7 {
		t.Fatalf("CounterValue=%d want 7", got)
	}
}

func TestMemorySinkConcurrentAdd(t *testing.T) {
	s := NewMemorySink()
	c := s.Counter("c")
	const goroutines = 16
	const per = 10000
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < per; j++ {
				c.Add(1)
			}
		}()
	}
	wg.Wait()
	want := uint64(goroutines * per)
	if got := c.Value(); got != want {
		t.Fatalf("counter=%d want %d", got, want)
	}
}

func TestMemorySinkGauge(t *testing.T) {
	s := NewMemorySink()
	g := s.Gauge("live")
	g.Add(5)
	g.Add(3)
	g.Add(-2)
	if g.Value() != 6 {
		t.Fatalf("gauge=%d want 6", g.Value())
	}
	g.Set(100)
	if g.Value() != 100 {
		t.Fatalf("gauge after Set=%d want 100", g.Value())
	}
}

func TestMemorySinkHistogramSnapshotIsSorted(t *testing.T) {
	s := NewMemorySink()
	h := s.Histogram("lat")
	for _, v := range []float64{3, 1, 2, 5, 4} {
		h.Observe(v)
	}
	got := s.HistogramSamples("lat")
	want := []float64{1, 2, 3, 4, 5}
	if len(got) != len(want) {
		t.Fatalf("len=%d want %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("sample[%d]=%v want %v", i, got[i], want[i])
		}
	}
}

func TestExpvarSinkPublishesAndPersists(t *testing.T) {
	s := NewExpvarSink("mirage_test_" + t.Name())
	c := s.Counter("c")
	c.Add(5)
	if got := c.Value(); got != 5 {
		t.Fatalf("Value=%d want 5", got)
	}
	g := s.Gauge("g")
	g.Set(11)
	if got := g.Value(); got != 11 {
		t.Fatalf("Value=%d want 11", got)
	}
	s.Histogram("h").Observe(0.123)
}
