package bbr2

import "testing"

func TestWindowedFilterTracksMaximum(t *testing.T) {
	f := NewMaxFilter(4)
	if f.HasValue() {
		t.Fatal("filter must start empty")
	}

	samples := []struct {
		round RoundTripCount
		value Bandwidth
	}{
		{0, 100 * BytesPerSecond},
		{1, 200 * BytesPerSecond},
		{2, 50 * BytesPerSecond},
		{3, 150 * BytesPerSecond},
	}
	for _, s := range samples {
		f.Update(s.value, s.round)
	}

	if got, want := f.GetBest(), 200*BytesPerSecond; got != want {
		t.Fatalf("best = %d, want %d", got, want)
	}

	// After the window has fully expired without a higher sample,
	// the best estimate must have been replaced.
	for r := RoundTripCount(4); r < 12; r++ {
		f.Update(10*BytesPerSecond, r)
	}
	if got := f.GetBest(); got > 200*BytesPerSecond {
		t.Fatalf("best should have decayed below the original peak, got %d", got)
	}
}

func TestWindowedFilterTracksMinimum(t *testing.T) {
	f := NewMinFilter(4)
	for round, v := range []Bandwidth{500, 300, 800, 700, 900} {
		f.Update(v*BytesPerSecond, RoundTripCount(round))
	}
	if got, want := f.GetBest(), 300*BytesPerSecond; got != want {
		t.Fatalf("min = %d, want %d", got, want)
	}
}

func TestWindowedFilterClear(t *testing.T) {
	f := NewMaxFilter(4)
	f.Update(123*BytesPerSecond, 0)
	f.Clear()
	if f.HasValue() {
		t.Fatal("Clear must reset HasValue")
	}
	if f.GetBest() != 0 {
		t.Fatal("Clear must reset best estimate")
	}
}
