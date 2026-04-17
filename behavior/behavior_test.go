package behavior

import (
	"testing"
	"time"

	"github.com/quic-go/quic-go"

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
	if d.HandshakeIdleTimeout != 10*time.Second {
		t.Fatalf("HandshakeIdleTimeout %v", d.HandshakeIdleTimeout)
	}
	if d.MaxUDPPayloadSize != 1452 {
		t.Fatalf("MaxUDPPayloadSize %d", d.MaxUDPPayloadSize)
	}
	if d.ActiveConnectionIDLimit != 8 {
		t.Fatalf("ActiveConnectionIDLimit %d", d.ActiveConnectionIDLimit)
	}
	if d.InitialMaxData != 15<<20 {
		t.Fatalf("InitialMaxData %d", d.InitialMaxData)
	}
	if d.InitialMaxStreamDataBidiLocal != 6<<20 {
		t.Fatalf("InitialMaxStreamDataBidiLocal %d", d.InitialMaxStreamDataBidiLocal)
	}
	if d.InitialMaxStreamsBidi != 100 {
		t.Fatalf("InitialMaxStreamsBidi %d", d.InitialMaxStreamsBidi)
	}
	if d.CIDRotateInterval != 5*time.Minute {
		t.Fatalf("CIDRotateInterval %v", d.CIDRotateInterval)
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
	tp := &transport.TransportParameters{
		DisableActiveMigration: true, // verify ApplyTo clears this
	}
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
	if tp.ActiveConnectionIDLimit != 8 {
		t.Fatalf("acid %d", tp.ActiveConnectionIDLimit)
	}
	if tp.InitialMaxData != 15<<20 {
		t.Fatalf("initial_max_data %d", tp.InitialMaxData)
	}
	if tp.InitialMaxStreamDataBidiLocal != 6<<20 {
		t.Fatalf("imsd_local %d", tp.InitialMaxStreamDataBidiLocal)
	}
	if tp.InitialMaxStreamDataBidiRemote != 6<<20 {
		t.Fatalf("imsd_remote %d", tp.InitialMaxStreamDataBidiRemote)
	}
	if tp.InitialMaxStreamDataUni != 6<<20 {
		t.Fatalf("imsd_uni %d", tp.InitialMaxStreamDataUni)
	}
	if tp.InitialMaxStreamsBidi != 100 {
		t.Fatalf("ims_bidi %d", tp.InitialMaxStreamsBidi)
	}
	if tp.InitialMaxStreamsUni != 100 {
		t.Fatalf("ims_uni %d", tp.InitialMaxStreamsUni)
	}
	if tp.DisableActiveMigration {
		t.Fatal("Chrome H3 must not advertise disable_active_migration")
	}
}

func TestApplyToQUICConfigFillsDefaults(t *testing.T) {
	cfg := Default()
	qc := &quic.Config{}
	ApplyToQUICConfig(qc, cfg)
	if qc.HandshakeIdleTimeout != 10*time.Second {
		t.Fatalf("handshake idle %v", qc.HandshakeIdleTimeout)
	}
	if qc.MaxIdleTimeout != 30*time.Second {
		t.Fatalf("idle %v", qc.MaxIdleTimeout)
	}
	if qc.InitialStreamReceiveWindow != 6<<20 {
		t.Fatalf("initial stream rwnd %d", qc.InitialStreamReceiveWindow)
	}
	if qc.MaxStreamReceiveWindow != 16<<20 {
		t.Fatalf("max stream rwnd %d", qc.MaxStreamReceiveWindow)
	}
	if qc.InitialConnectionReceiveWindow != 15<<20 {
		t.Fatalf("initial conn rwnd %d", qc.InitialConnectionReceiveWindow)
	}
	if qc.MaxConnectionReceiveWindow != 24<<20 {
		t.Fatalf("max conn rwnd %d", qc.MaxConnectionReceiveWindow)
	}
	if qc.MaxIncomingStreams != 100 {
		t.Fatalf("max bidi %d", qc.MaxIncomingStreams)
	}
	if qc.MaxIncomingUniStreams != 100 {
		t.Fatalf("max uni %d", qc.MaxIncomingUniStreams)
	}
	if qc.InitialPacketSize != 1252 {
		t.Fatalf("initial pkt size %d", qc.InitialPacketSize)
	}
	if qc.KeepAlivePeriod != 0 {
		t.Fatalf("KeepAlivePeriod must stay 0 for Chrome alignment, got %v", qc.KeepAlivePeriod)
	}
}

func TestApplyToQUICConfigPreservesOverrides(t *testing.T) {
	cfg := Default()
	qc := &quic.Config{
		HandshakeIdleTimeout: 7 * time.Second,
		MaxIncomingStreams:   42,
	}
	ApplyToQUICConfig(qc, cfg)
	if qc.HandshakeIdleTimeout != 7*time.Second {
		t.Fatalf("override clobbered: %v", qc.HandshakeIdleTimeout)
	}
	if qc.MaxIncomingStreams != 42 {
		t.Fatalf("override clobbered: %d", qc.MaxIncomingStreams)
	}
	if qc.MaxIdleTimeout != 30*time.Second {
		t.Fatalf("default not filled when caller left zero: %v", qc.MaxIdleTimeout)
	}
}
