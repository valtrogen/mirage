package handshake

import (
	"net"
	"sync"
	"time"
)

// rateLimiter is a per-source-IP token bucket. It guards the AES-GCM
// decryption path on the server: an attacker that floods Initial
// packets at line rate can otherwise burn server CPU per junk packet.
//
// The bucket refills at a steady rate and never overflows past Burst.
// Requests above the rate are rejected without further work; the
// dispatcher then drops the datagram.
//
// rateLimiter is safe for concurrent use. Idle buckets are reaped on a
// best-effort basis from the calling goroutine; there is no background
// timer.
type rateLimiter struct {
	rate  float64       // tokens per second
	burst float64       // bucket size
	idle  time.Duration // idle bucket retention

	mu      sync.Mutex
	buckets map[string]*tokenBucket
	lastGC  time.Time
}

type tokenBucket struct {
	tokens    float64
	updatedAt time.Time
}

// newRateLimiter returns a limiter that issues `rate` tokens/second to
// each source IP, with up to `burst` accumulated tokens. Buckets idle
// for longer than 5*idle are reclaimed.
func newRateLimiter(rate, burst float64, idle time.Duration) *rateLimiter {
	if rate <= 0 {
		rate = 1
	}
	if burst <= 0 {
		burst = rate
	}
	if idle <= 0 {
		idle = time.Minute
	}
	return &rateLimiter{
		rate:    rate,
		burst:   burst,
		idle:    idle,
		buckets: make(map[string]*tokenBucket),
	}
}

// Allow consumes one token from the bucket keyed by addr's IP. It
// returns true when the request is within the budget.
func (r *rateLimiter) Allow(addr net.Addr) bool {
	return r.AllowAt(addr, time.Now())
}

// AllowAt is like Allow but uses an explicit clock; tests pass a fixed
// time so the bucket maths is deterministic.
func (r *rateLimiter) AllowAt(addr net.Addr, now time.Time) bool {
	key := bucketKey(addr)
	r.mu.Lock()
	defer r.mu.Unlock()

	r.gcLocked(now)

	b, ok := r.buckets[key]
	if !ok {
		b = &tokenBucket{tokens: r.burst, updatedAt: now}
		r.buckets[key] = b
	}
	elapsed := now.Sub(b.updatedAt).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * r.rate
		if b.tokens > r.burst {
			b.tokens = r.burst
		}
		b.updatedAt = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens -= 1
	return true
}

// Size returns the number of live buckets. Intended for tests and
// gauges.
func (r *rateLimiter) Size() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.buckets)
}

func (r *rateLimiter) gcLocked(now time.Time) {
	if !r.lastGC.IsZero() && now.Sub(r.lastGC) < r.idle {
		return
	}
	r.lastGC = now
	cutoff := now.Add(-5 * r.idle)
	for k, b := range r.buckets {
		if b.updatedAt.Before(cutoff) {
			delete(r.buckets, k)
		}
	}
}

// bucketKey is the limiter key for addr. UDP and TCP addresses are
// keyed by the source IP only; everything else falls back to the full
// string form (which is still a useful, if narrower, scope).
func bucketKey(addr net.Addr) string {
	switch a := addr.(type) {
	case *net.UDPAddr:
		return a.IP.String()
	case *net.TCPAddr:
		return a.IP.String()
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return addr.String()
	}
	return host
}
