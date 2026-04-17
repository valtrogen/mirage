package congestion

import (
	"testing"
	"time"
)

func TestRTTStatsZeroValue(t *testing.T) {
	r := NewRTTStats()
	if r.HasMeasurement() {
		t.Fatal("fresh RTTStats should report no measurement")
	}
	if r.MinRTT() != 0 || r.SmoothedRTT() != 0 || r.LatestRTT() != 0 {
		t.Fatal("fresh RTTStats should report zero RTTs")
	}
	if r.PTO() != 0 {
		t.Fatal("fresh RTTStats should have zero PTO")
	}
	if r.MaxAckDelay() != 25*time.Millisecond {
		t.Fatalf("default MaxAckDelay should be 25ms, got %v", r.MaxAckDelay())
	}
}

func TestRTTStatsFirstSampleSeedsSmoothed(t *testing.T) {
	r := NewRTTStats()
	r.UpdateRTT(50*time.Millisecond, 0)
	if !r.HasMeasurement() {
		t.Fatal("UpdateRTT should mark measurement present")
	}
	if r.MinRTT() != 50*time.Millisecond {
		t.Fatalf("MinRTT = %v, want 50ms", r.MinRTT())
	}
	if r.SmoothedRTT() != 50*time.Millisecond {
		t.Fatalf("first sample should seed smoothed; got %v", r.SmoothedRTT())
	}
	if r.LatestRTT() != 50*time.Millisecond {
		t.Fatalf("LatestRTT = %v, want 50ms", r.LatestRTT())
	}
	if r.MeanDeviation() != 25*time.Millisecond {
		t.Fatalf("mean dev should be sample/2; got %v", r.MeanDeviation())
	}
}

func TestRTTStatsEWMA(t *testing.T) {
	r := NewRTTStats()
	r.UpdateRTT(100*time.Millisecond, 0)
	r.UpdateRTT(200*time.Millisecond, 0)
	// 7/8*100 + 1/8*200 = 87.5 + 25 = 112.5ms
	want := time.Duration(112.5 * float64(time.Millisecond))
	if got := r.SmoothedRTT(); got != want {
		t.Fatalf("smoothed after 100,200 = %v, want %v", got, want)
	}
	if got := r.MinRTT(); got != 100*time.Millisecond {
		t.Fatalf("MinRTT should still be 100ms, got %v", got)
	}
}

func TestRTTStatsAckDelaySubtracted(t *testing.T) {
	r := NewRTTStats()
	r.UpdateRTT(100*time.Millisecond, 0)
	// sample 200ms, ack_delay 50ms: adjusted=150ms, still ≥ minRTT(100ms)
	r.UpdateRTT(200*time.Millisecond, 50*time.Millisecond)
	// 7/8*100 + 1/8*150 = 87.5 + 18.75 = 106.25ms
	want := time.Duration(106.25 * float64(time.Millisecond))
	if got := r.SmoothedRTT(); got != want {
		t.Fatalf("smoothed with ack_delay = %v, want %v", got, want)
	}
}

func TestRTTStatsAckDelayIgnoredWhenSubtractDropsBelowMin(t *testing.T) {
	r := NewRTTStats()
	r.UpdateRTT(100*time.Millisecond, 0)
	// sample 110ms, ack_delay 50ms: adjusted=60ms, below minRTT(100ms)
	// → use raw 110ms, not adjusted.
	r.UpdateRTT(110*time.Millisecond, 50*time.Millisecond)
	// 7/8*100 + 1/8*110 = 87.5 + 13.75 = 101.25ms
	want := time.Duration(101.25 * float64(time.Millisecond))
	if got := r.SmoothedRTT(); got != want {
		t.Fatalf("smoothed = %v, want %v (ack_delay should be ignored)", got, want)
	}
}

func TestRTTStatsIgnoresNonPositiveSample(t *testing.T) {
	r := NewRTTStats()
	r.UpdateRTT(0, 0)
	r.UpdateRTT(-time.Millisecond, 0)
	if r.HasMeasurement() {
		t.Fatal("non-positive samples should be ignored")
	}
}

func TestRTTStatsPTO(t *testing.T) {
	r := NewRTTStats()
	r.SetMaxAckDelay(20 * time.Millisecond)
	r.UpdateRTT(50*time.Millisecond, 0)
	// smoothed=50ms, mean_dev=25ms → 4*25=100ms (clamp ≥1ms ok)
	// PTO = 50 + 100 + 20 = 170ms
	if got := r.PTO(); got != 170*time.Millisecond {
		t.Fatalf("PTO = %v, want 170ms", got)
	}
}

func TestRTTStatsConcurrentSafe(t *testing.T) {
	r := NewRTTStats()
	r.UpdateRTT(50*time.Millisecond, 0)

	done := make(chan struct{})
	go func() {
		for i := 0; i < 1000; i++ {
			r.UpdateRTT(time.Duration(50+i)*time.Millisecond, 0)
		}
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		_ = r.SmoothedRTT()
		_ = r.MinRTT()
		_ = r.PTO()
	}
	<-done
	if r.MinRTT() != 50*time.Millisecond {
		t.Fatalf("MinRTT after concurrent updates = %v, want 50ms", r.MinRTT())
	}
}
