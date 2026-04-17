// BBRv2 clock interface
// src from: https://github.com/cloudflare/quiche

package bbr2

import "time"

// Clock returns the current wall-clock time. Tests inject a frozen
// or stepped clock to exercise BBRv2 state transitions
// deterministically; production code uses DefaultClock.
type Clock interface {
	Now() time.Time
}

// DefaultClock returns time.Now() unless TimeFunc is set, in which
// case it delegates. Tests typically install a TimeFunc that walks a
// scripted timeline.
type DefaultClock struct {
	TimeFunc func() time.Time
}

// Now returns the current time, delegating to TimeFunc when set.
func (c DefaultClock) Now() time.Time {
	if c.TimeFunc != nil {
		return c.TimeFunc()
	}
	return time.Now()
}
