package behavior

import (
	"testing"
	"time"

	"github.com/valtrogen/mirage/transport"
)

func TestDefaultMatchesChromeH3(t *testing.T) {
	d := Default()
	if d.PingInterval != 30*time.Second {
		t.Fatalf("PingInterval %v", d.PingInterval)
	}
	if d.MaxAckDelay != 25*time.Millisecond {
		t.Fatalf("MaxAckDelay %v", d.MaxAckDelay)
	}
	if d.AckDelayExponent != 3 {
		t.Fatalf("AckDelayExponent %d", d.AckDelayExponent)
	}
	if d.MaxIdleTimeout != 30*time.Second {
		t.Fatalf("MaxIdleTimeout %v", d.MaxIdleTimeout)
	}
	if d.MaxUDPPayloadSize != 1452 {
		t.Fatalf("MaxUDPPayloadSize %d", d.MaxUDPPayloadSize)
	}
	if d.ActiveConnectionIDLimit != 4 {
		t.Fatalf("ActiveConnectionIDLimit %d", d.ActiveConnectionIDLimit)
	}
}

func TestPingClockTriggersAfterIdle(t *testing.T) {
	c := NewPingClock(50 * time.Millisecond)
	if c.ShouldPing(time.Now()) {
		t.Fatal("fresh clock should not ping immediately")
	}
	time.Sleep(60 * time.Millisecond)
	if !c.ShouldPing(time.Now()) {
		t.Fatal("should ping after idle interval")
	}
	c.Activity(time.Now())
	if c.ShouldPing(time.Now()) {
		t.Fatal("activity should reset deadline")
	}
}

func TestPMTUSearchProgresses(t *testing.T) {
	s := NewPMTUSearch(Default())
	start := s.Current()
	now := time.Now()
	if !s.ShouldProbe(now) {
		t.Fatal("should probe initially")
	}
	probe := s.NextProbeSize()
	if probe <= start {
		t.Fatalf("probe %d not larger than current %d", probe, start)
	}
	s.Sent(probe, now)
	s.Confirmed(probe)
	if s.Current() != probe {
		t.Fatalf("current not updated: %d", s.Current())
	}
	// Immediately afterwards we should not probe again until the
	// interval elapses.
	if s.ShouldProbe(now.Add(time.Millisecond)) {
		t.Fatal("should respect search interval")
	}
}

func TestPMTUSearchStopsAtMaxProbes(t *testing.T) {
	cfg := Default()
	cfg.PMTUMaxProbes = 1
	s := NewPMTUSearch(cfg)
	now := time.Now()
	probe := s.NextProbeSize()
	s.Sent(probe, now)
	if s.NextProbeSize() != 0 {
		t.Fatal("should stop after max probes")
	}
}

func TestApplyToTransportParameters(t *testing.T) {
	cfg := Default()
	tp := &transport.TransportParameters{}
	ApplyToTransportParameters(tp, cfg)
	if tp.MaxIdleTimeoutMillis != 30000 {
		t.Fatalf("idle %d", tp.MaxIdleTimeoutMillis)
	}
	if tp.MaxAckDelayMillis != 25 {
		t.Fatalf("ack %d", tp.MaxAckDelayMillis)
	}
	if tp.AckDelayExponent != 3 {
		t.Fatalf("exp %d", tp.AckDelayExponent)
	}
	if tp.MaxUDPPayloadSize != 1452 {
		t.Fatalf("udp %d", tp.MaxUDPPayloadSize)
	}
	if tp.ActiveConnectionIDLimit != 4 {
		t.Fatalf("acid %d", tp.ActiveConnectionIDLimit)
	}
}
