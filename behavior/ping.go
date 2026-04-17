package behavior

import (
	"sync"
	"time"
)

// PingClock fires Tick once every PingInterval as long as it has not
// been fed activity. Any data sent or received resets the timer, which
// matches Chrome's "PING only on real idle" behaviour.
//
// Zero value is not usable; construct with NewPingClock.
type PingClock struct {
	interval time.Duration

	mu       sync.Mutex
	lastSeen time.Time
}

// NewPingClock returns a PingClock with the given idle interval. The
// clock starts assuming activity at time.Now() so a freshly built
// connection does not immediately want to PING.
func NewPingClock(interval time.Duration) *PingClock {
	return &PingClock{interval: interval, lastSeen: time.Now()}
}

// Activity records that traffic was seen at t. Callers should invoke
// this on every datagram in or out so the PING timer resets together
// with real traffic.
func (p *PingClock) Activity(t time.Time) {
	p.mu.Lock()
	if t.After(p.lastSeen) {
		p.lastSeen = t
	}
	p.mu.Unlock()
}

// NextDeadline reports the absolute time at which the next PING should
// be issued, given the most recent Activity.
func (p *PingClock) NextDeadline() time.Time {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.lastSeen.Add(p.interval)
}

// ShouldPing reports whether the current time is at or past the next
// PING deadline.
func (p *PingClock) ShouldPing(now time.Time) bool {
	return !now.Before(p.NextDeadline())
}
