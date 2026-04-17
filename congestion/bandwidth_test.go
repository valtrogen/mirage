package congestion

import (
	"testing"
	"time"
)

func TestBandwidthFromDelta(t *testing.T) {
	cases := []struct {
		name  string
		bytes ByteCount
		delta time.Duration
		want  uint64 // bytes per second
	}{
		{"1KB in 1s", 1000, time.Second, 1000},
		{"1MB in 1s", 1_000_000, time.Second, 1_000_000},
		{"1KB in 10ms", 1000, 10 * time.Millisecond, 100_000},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := BandwidthFromDelta(tc.bytes, tc.delta).BytesPerSecond()
			if got != tc.want {
				t.Fatalf("got %d B/s, want %d B/s", got, tc.want)
			}
		})
	}
}

func TestBandwidthFromDeltaZero(t *testing.T) {
	if got := BandwidthFromDelta(1, 0); got != InfBandwidth {
		t.Fatalf("delta=0 should be InfBandwidth, got %d", got)
	}
}

func TestBandwidthBytesInDuration(t *testing.T) {
	bps := BandwidthFromBytesPerSecond(1_000_000)
	if got := bps.BytesInDuration(time.Second); got != 1_000_000 {
		t.Fatalf("1s @ 1MB/s = %d, want 1_000_000", got)
	}
	if got := bps.BytesInDuration(100 * time.Millisecond); got != 100_000 {
		t.Fatalf("100ms @ 1MB/s = %d, want 100_000", got)
	}
	if got := bps.BytesInDuration(0); got != 0 {
		t.Fatalf("zero duration should yield 0 bytes, got %d", got)
	}
	if got := bps.BytesInDuration(-time.Second); got != 0 {
		t.Fatalf("negative duration should yield 0 bytes, got %d", got)
	}
}

func TestBandwidthMul(t *testing.T) {
	bps := BandwidthFromBytesPerSecond(1_000_000)
	if got := bps.Mul(2.0).BytesPerSecond(); got != 2_000_000 {
		t.Fatalf("2x = %d, want 2_000_000", got)
	}
	if got := bps.Mul(0.5).BytesPerSecond(); got != 500_000 {
		t.Fatalf("0.5x = %d, want 500_000", got)
	}
	if got := bps.Mul(0); got != 0 {
		t.Fatalf("0x should be 0, got %d", got)
	}
	if got := bps.Mul(-1); got != 0 {
		t.Fatalf("negative factor should be 0, got %d", got)
	}
	if got := InfBandwidth.Mul(2); !got.IsInfinite() {
		t.Fatalf("Inf * 2 should saturate to Inf, got %d", got)
	}
}

func TestBandwidthZeroAndInf(t *testing.T) {
	if !Bandwidth(0).IsZero() || Bandwidth(0).IsInfinite() {
		t.Fatal("0 should be zero, not infinite")
	}
	if InfBandwidth.IsZero() || !InfBandwidth.IsInfinite() {
		t.Fatal("InfBandwidth should be infinite, not zero")
	}
}
