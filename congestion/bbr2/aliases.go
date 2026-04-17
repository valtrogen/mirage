// Local aliases that re-export the parent congestion package's
// types under their original cloudflare/quiche names. The aliases
// keep the body of the BBRv2 port readable without prefixing every
// reference with `congestion.` and also let the small set of helper
// functions (BandwidthFromBytesAndTimeDelta, BytesFromBandwidth-
// AndTimeDelta) used throughout the port live in one place rather
// than being scattered across the parent package.

package bbr2

import (
	"time"

	"github.com/valtrogen/mirage/congestion"
)

// Bandwidth is the unit-bearing rate type used throughout BBRv2.
type Bandwidth = congestion.Bandwidth

// Bandwidth unit constants, re-exported for ergonomic in-package use.
const (
	BitsPerSecond   = congestion.BitsPerSecond
	BytesPerSecond  = congestion.BytesPerSecond
	KBitsPerSecond  = congestion.KBitsPerSecond
	KBytesPerSecond = congestion.KBytesPerSecond
	MBitsPerSecond  = congestion.MBitsPerSecond
	MBytesPerSecond = congestion.MBytesPerSecond
	GBitsPerSecond  = congestion.GBitsPerSecond
	GBytesPerSecond = congestion.GBytesPerSecond
	infBandwidth    = congestion.InfBandwidth
)

// BandwidthFromBytesAndTimeDelta is the rate implied by transferring
// bytes over delta. It mirrors the cloudflare/quiche helper of the
// same name.
func BandwidthFromBytesAndTimeDelta(bytes congestion.ByteCount, delta time.Duration) Bandwidth {
	return congestion.BandwidthFromDelta(bytes, delta)
}

// BandwidthFromBytesPerSecond is the cloudflare/quiche-style helper
// for constructing a Bandwidth from an integer bytes/sec value.
func BandwidthFromBytesPerSecond(bps uint64) Bandwidth {
	return congestion.BandwidthFromBytesPerSecond(bps)
}

// BytesFromBandwidthAndTimeDelta inverts BandwidthFromBytesAndTimeDelta:
// the number of bytes b can transfer in delta.
func BytesFromBandwidthAndTimeDelta(b Bandwidth, delta time.Duration) congestion.ByteCount {
	return b.BytesInDuration(delta)
}

// neverSendTime is the absolute-time sentinel BBR2 returns from
// TimeUntilSend when the controller forbids further sends entirely.
// Callers compare it against the current wall-clock time and treat
// any value at or past this point as "blocked, wait for the next
// state transition". The constant is far enough in the future that
// no real wall clock will ever reach it.
var neverSendTime = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)
