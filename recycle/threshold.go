package recycle

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"sync/atomic"
	"time"
)

// Bounds describe the inclusive interval from which a per-connection
// recycle threshold is sampled. The server picks a fresh Threshold for
// each connection so that observers cannot tell apart two flows by their
// recycle moment.
type Bounds struct {
	AgeMin   time.Duration
	AgeMax   time.Duration
	BytesMin uint64
	BytesMax uint64
}

// Default thresholds: 90-180min or 3-8GB. These match the data-plane
// behaviour clause: real long-lived QUIC flows (cloud gaming, drive
// sync, video upload) sit in this range, so a flow that recycles inside
// it is not statistically distinguishable from them.
func DefaultBounds() Bounds {
	return Bounds{
		AgeMin:   90 * time.Minute,
		AgeMax:   180 * time.Minute,
		BytesMin: 3 << 30,
		BytesMax: 8 << 30,
	}
}

// Threshold is the realised, per-connection recycle target. The
// connection should rotate as soon as either dimension is crossed.
type Threshold struct {
	Age   time.Duration
	Bytes uint64
}

// ErrInvalidBounds is returned when min > max in either dimension.
var ErrInvalidBounds = errors.New("mirage/recycle: bounds min > max")

// Sample draws a uniform Threshold from b. r is the source of
// randomness (crypto/rand in production, a deterministic stream in
// tests). On error it falls back to the upper bound, which is the
// strictest defensible choice.
func (b Bounds) Sample(r io.Reader) (Threshold, error) {
	if b.AgeMin > b.AgeMax || b.BytesMin > b.BytesMax {
		return Threshold{}, ErrInvalidBounds
	}
	if r == nil {
		r = rand.Reader
	}
	age, err := uniformDuration(r, b.AgeMin, b.AgeMax)
	if err != nil {
		return Threshold{Age: b.AgeMax, Bytes: b.BytesMax}, err
	}
	bytes, err := uniformUint64(r, b.BytesMin, b.BytesMax)
	if err != nil {
		return Threshold{Age: age, Bytes: b.BytesMax}, err
	}
	return Threshold{Age: age, Bytes: bytes}, nil
}

func uniformDuration(r io.Reader, lo, hi time.Duration) (time.Duration, error) {
	if hi == lo {
		return lo, nil
	}
	delta, err := uniformUint64(r, 0, uint64(hi-lo))
	if err != nil {
		return 0, err
	}
	return lo + time.Duration(delta), nil
}

func uniformUint64(r io.Reader, lo, hi uint64) (uint64, error) {
	if hi == lo {
		return lo, nil
	}
	span := hi - lo + 1
	var buf [8]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return 0, err
	}
	return lo + binary.BigEndian.Uint64(buf[:])%span, nil
}

// Tracker watches a single connection's age and byte count and reports
// when its Threshold is reached. Tracker is safe for concurrent use:
// AddBytes uses an atomic counter, Reached only reads.
type Tracker struct {
	threshold Threshold
	startedAt time.Time
	bytes     atomic.Uint64
}

// NewTracker starts a tracker that compares against th. Its clock
// origin is time.Now().
func NewTracker(th Threshold) *Tracker {
	return &Tracker{threshold: th, startedAt: time.Now()}
}

// Threshold returns the realised limit this tracker is comparing
// against.
func (t *Tracker) Threshold() Threshold { return t.threshold }

// AddBytes increments the byte counter. n is typically the size of an
// outbound or inbound application-layer payload chunk.
func (t *Tracker) AddBytes(n uint64) { t.bytes.Add(n) }

// Bytes returns the accumulated counter.
func (t *Tracker) Bytes() uint64 { return t.bytes.Load() }

// Age returns the duration since NewTracker was called.
func (t *Tracker) Age() time.Duration { return time.Since(t.startedAt) }

// Reached reports whether either the age or the byte threshold has
// been crossed.
func (t *Tracker) Reached() bool {
	if t.threshold.Age > 0 && t.Age() >= t.threshold.Age {
		return true
	}
	if t.threshold.Bytes > 0 && t.bytes.Load() >= t.threshold.Bytes {
		return true
	}
	return false
}
