package replay

import "sync"

// SlidingWindow is an IPSec-style anti-replay window over monotonically
// increasing 64-bit sequence numbers. It rejects duplicates and
// out-of-order packets that fall more than (Width-1) behind the highest
// number ever accepted.
//
// The default Width is 64. A SlidingWindow is safe for concurrent use.
type SlidingWindow struct {
	mu     sync.Mutex
	width  uint64
	last   uint64 // highest seq ever accepted
	bitmap uint64 // bit i is "seq (last - i) is seen", i in [0, width-1]
	seeded bool   // false until the first Check call
}

// NewSlidingWindow returns a window of the given width. Width must be in
// [1, 64]; values outside that range are clamped to 64.
func NewSlidingWindow(width int) *SlidingWindow {
	if width <= 0 || width > 64 {
		width = 64
	}
	return &SlidingWindow{width: uint64(width)}
}

// Check tests whether seq is acceptable. If it is, the window is updated
// in place and Check returns true. If seq is a duplicate or too far in
// the past, the window is left unchanged and Check returns false.
//
// The first ever Check accepts any seq and seeds the window from it.
func (w *SlidingWindow) Check(seq uint64) bool {
	w.mu.Lock()
	defer w.mu.Unlock()

	if !w.seeded {
		w.seeded = true
		w.last = seq
		w.bitmap = 1
		return true
	}

	if seq > w.last {
		shift := seq - w.last
		if shift >= 64 {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.last = seq
		return true
	}

	diff := w.last - seq
	if diff >= w.width {
		return false
	}
	mask := uint64(1) << diff
	if w.bitmap&mask != 0 {
		return false
	}
	w.bitmap |= mask
	return true
}

// Last returns the highest sequence number ever accepted, or zero if
// nothing has been accepted yet.
func (w *SlidingWindow) Last() uint64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.last
}
