package congestion

import (
	"math"
	"time"
)

// Bandwidth represents a data rate. The unit is bits per second so
// that a Bandwidth literal is directly comparable across helpers; use
// the conversion helpers below to move between bytes and bits.
type Bandwidth uint64

const (
	// BitsPerSecond is the canonical Bandwidth unit.
	BitsPerSecond Bandwidth = 1
	// BytesPerSecond is 8 BitsPerSecond.
	BytesPerSecond Bandwidth = 8 * BitsPerSecond
	// KBitsPerSecond is 1000 BitsPerSecond (decimal, matching network gear).
	KBitsPerSecond Bandwidth = 1000 * BitsPerSecond
	// KBytesPerSecond is 8 KBitsPerSecond.
	KBytesPerSecond Bandwidth = 8 * KBitsPerSecond
	// MBitsPerSecond is 1000 KBitsPerSecond.
	MBitsPerSecond Bandwidth = 1000 * KBitsPerSecond
	// MBytesPerSecond is 8 MBitsPerSecond.
	MBytesPerSecond Bandwidth = 8 * MBitsPerSecond
	// GBitsPerSecond is 1000 MBitsPerSecond.
	GBitsPerSecond Bandwidth = 1000 * MBitsPerSecond
	// GBytesPerSecond is 8 GBitsPerSecond.
	GBytesPerSecond Bandwidth = 8 * GBitsPerSecond

	// InfBandwidth is the sentinel returned when no rate limit applies.
	InfBandwidth Bandwidth = math.MaxUint64
)

// BandwidthFromDelta computes the bandwidth implied by transferring
// bytes over delta. delta == 0 yields InfBandwidth.
func BandwidthFromDelta(bytes ByteCount, delta time.Duration) Bandwidth {
	if delta <= 0 {
		return InfBandwidth
	}
	return Bandwidth(uint64(bytes) * uint64(time.Second) / uint64(delta) * uint64(BytesPerSecond))
}

// BandwidthFromBytesPerSecond converts a raw bytes/second value into a
// Bandwidth.
func BandwidthFromBytesPerSecond(bps uint64) Bandwidth {
	return Bandwidth(bps * uint64(BytesPerSecond))
}

// BytesPerSecond returns b expressed as bytes per second.
func (b Bandwidth) BytesPerSecond() uint64 {
	return uint64(b) / uint64(BytesPerSecond)
}

// BytesInDuration returns the number of bytes transferable at b in d.
// Returns 0 for negative durations.
func (b Bandwidth) BytesInDuration(d time.Duration) ByteCount {
	if d <= 0 {
		return 0
	}
	return ByteCount(uint64(b) * uint64(d) / uint64(time.Second) / uint64(BytesPerSecond))
}

// Mul scales b by factor. The result saturates at InfBandwidth on
// overflow and never returns negative values for negative factors.
func (b Bandwidth) Mul(factor float64) Bandwidth {
	if factor <= 0 {
		return 0
	}
	scaled := float64(b) * factor
	if scaled >= float64(InfBandwidth) {
		return InfBandwidth
	}
	return Bandwidth(scaled)
}

// IsZero reports whether b is the zero rate.
func (b Bandwidth) IsZero() bool { return b == 0 }

// IsInfinite reports whether b is the unlimited sentinel.
func (b Bandwidth) IsInfinite() bool { return b == InfBandwidth }
