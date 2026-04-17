package handshake

import (
	"net"
	"testing"
	"time"
)

func addr(ip string) net.Addr {
	return &net.UDPAddr{IP: net.ParseIP(ip), Port: 1234}
}

func TestRateLimiterBurstThenRefill(t *testing.T) {
	now := time.Unix(0, 0)
	r := newRateLimiter(10, 5, time.Minute)
	a := addr("10.0.0.1")
	for i := 0; i < 5; i++ {
		if !r.AllowAt(a, now) {
			t.Fatalf("burst[%d] denied", i)
		}
	}
	if r.AllowAt(a, now) {
		t.Fatal("post-burst request allowed before refill")
	}
	if !r.AllowAt(a, now.Add(110*time.Millisecond)) {
		t.Fatal("refilled token denied")
	}
}

func TestRateLimiterPerSourceIsolation(t *testing.T) {
	now := time.Unix(0, 0)
	r := newRateLimiter(1, 1, time.Minute)
	if !r.AllowAt(addr("10.0.0.1"), now) {
		t.Fatal("first IP denied")
	}
	if r.AllowAt(addr("10.0.0.1"), now) {
		t.Fatal("first IP second denied")
	}
	if !r.AllowAt(addr("10.0.0.2"), now) {
		t.Fatal("second IP rejected")
	}
}

func TestRateLimiterPortDoesNotAffectScope(t *testing.T) {
	now := time.Unix(0, 0)
	r := newRateLimiter(1, 1, time.Minute)
	a := &net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 1}
	b := &net.UDPAddr{IP: net.ParseIP("10.0.0.5"), Port: 2}
	if !r.AllowAt(a, now) {
		t.Fatal("first port denied")
	}
	if r.AllowAt(b, now) {
		t.Fatal("port 2 should share the IP bucket")
	}
}

func TestRateLimiterIdleEviction(t *testing.T) {
	idle := 100 * time.Millisecond
	r := newRateLimiter(10, 5, idle)
	r.AllowAt(addr("10.0.0.1"), time.Unix(0, 0))
	if r.Size() != 1 {
		t.Fatalf("size=%d want 1", r.Size())
	}
	// Force GC by advancing time well past 5*idle
	r.AllowAt(addr("10.0.0.2"), time.Unix(0, 0).Add(10*time.Second))
	if r.Size() != 1 {
		t.Fatalf("size=%d want 1 (10.0.0.1 evicted)", r.Size())
	}
}
