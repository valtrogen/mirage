package handshake

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/metrics"
)

// TestServerDrainNoConnsCompletes verifies the drain fast-path when no
// connections are alive: Drain must return promptly without waiting on
// the context deadline.
func TestServerDrainNoConnsCompletes(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pc.Close()

	mk := make([]byte, 32)
	rand.Read(mk)

	srv := &Server{
		PacketConn:    pc,
		TLSConfig:     &tls.Config{Certificates: nil, NextProtos: []string{"h3"}, GetCertificate: nil},
		MasterKey:     mk,
		Authenticator: adapter.UserAuthenticatorFunc(func(context.Context, []byte) (adapter.UserID, error) { return adapter.UserID{}, nil }),
	}
	srv.TLSConfig = selfSignedTLSConfig(t, "drain2.test")
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	if err := srv.Drain(ctx); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("Drain blocked %v with no live conns", elapsed)
	}
}

func TestDispatcherRateLimitsInitial(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)

	d, server := newDispatcherForTest(t, mk)
	defer server.Close()
	d.InitialRatePerSec = 0.0001 // 1 token per ~3 hours
	d.InitialRateBurst = 1
	sink := metrics.NewMemorySink()
	d.Metrics = sink
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer d.Close()

	srvAddr := server.LocalAddr().(*net.UDPAddr)

	// Send from many distinct source ports so each datagram is a new
	// 4-tuple and bypasses the cached-session fast path. They all share
	// one source IP, so the per-IP token bucket is exhausted after the
	// first packet (burst=1) and the rest must be denied.
	var sockets []*net.UDPConn
	defer func() {
		for _, s := range sockets {
			_ = s.Close()
		}
	}()
	for i := 0; i < 32; i++ {
		c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatalf("listen %d: %v", i, err)
		}
		sockets = append(sockets, c)
		if _, err := c.WriteToUDP([]byte("garbage"), srvAddr); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if sink.CounterValue("dispatcher.rate_limited") > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("no rate-limited datagrams; rate_limited=%d drop=%d sessions=%d",
		sink.CounterValue("dispatcher.rate_limited"),
		sink.CounterValue("dispatcher.drop"),
		sink.GaugeValue("dispatcher.sessions"))
}
