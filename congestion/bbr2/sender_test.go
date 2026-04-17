package bbr2

import (
	"testing"
	"time"

	"github.com/valtrogen/mirage/congestion"
)

// scriptedClock walks a deterministic timeline that the test advances
// by hand. It is mandatory for BBR2 tests because mode transitions
// depend on the relationship between sent-time and ack-time, and the
// system clock can drift across CI runs.
type scriptedClock struct {
	now time.Time
}

func (c *scriptedClock) Now() time.Time { return c.now }
func (c *scriptedClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func TestBBR2SenderInitialState(t *testing.T) {
	s := NewBBR2Sender(DefaultClock{}, 1200, 0, false)
	if s.Mode() != ModeStartup {
		t.Fatalf("initial mode = %v, want STARTUP", s.Mode())
	}
	if !s.InSlowStart() {
		t.Fatal("BBR2 should report InSlowStart while in STARTUP")
	}
	wantCwnd := congestion.ByteCount(InitialCongestionWindowPackets) * 1200
	if s.GetCongestionWindow() != wantCwnd {
		t.Fatalf("initial cwnd = %d, want %d", s.GetCongestionWindow(), wantCwnd)
	}
	if s.PacingRate().IsZero() {
		t.Fatal("initial pacing rate must be non-zero")
	}
}

func TestBBR2SenderCanSendBelowCwnd(t *testing.T) {
	s := NewBBR2Sender(DefaultClock{}, 1200, 0, false)
	cwnd := s.GetCongestionWindow()
	if !s.CanSend(0) {
		t.Fatal("CanSend(0) must be true")
	}
	if !s.CanSend(cwnd - 1) {
		t.Fatal("CanSend(cwnd-1) must be true")
	}
	if s.CanSend(cwnd) {
		t.Fatal("CanSend(cwnd) must be false")
	}
}

func TestBBR2SenderTimeUntilSendBlockedAtCwnd(t *testing.T) {
	s := NewBBR2Sender(DefaultClock{}, 1200, 0, false)
	at := s.TimeUntilSend(s.GetCongestionWindow())
	if !at.Equal(neverSendTime) {
		t.Fatalf("TimeUntilSend at cwnd = %v, want neverSendTime", at)
	}
}

// TestBBR2SenderAckLossLifecycle drives the sender through a short
// in-flight burst followed by acks and a single loss. The point of
// the test is not to validate BBR's bandwidth math (that lives in
// the upstream rust suite) but to prove the Go port stays self-
// consistent — no panics, monotonically updated state, cwnd never
// dropping below the configured floor.
func TestBBR2SenderAckLossLifecycle(t *testing.T) {
	clock := &scriptedClock{now: time.Unix(0, 0)}
	s := NewBBR2Sender(clock, 1200, 0, false)

	const inFlightPackets = 8
	type outstanding struct {
		pn       congestion.PacketNumber
		bytes    congestion.ByteCount
		sentAt   time.Time
	}
	pending := make([]outstanding, 0, inFlightPackets)

	var inFlight congestion.ByteCount
	for i := 0; i < inFlightPackets; i++ {
		pn := congestion.PacketNumber(i + 1)
		s.OnPacketSent(clock.Now(), inFlight, pn, 1200, true)
		pending = append(pending, outstanding{pn: pn, bytes: 1200, sentAt: clock.Now()})
		inFlight += 1200
		clock.advance(100 * time.Microsecond)
	}

	if s.GetCongestionWindow() < congestion.ByteCount(minCongestionWindowPackets)*1200 {
		t.Fatalf("cwnd dropped below floor: %d", s.GetCongestionWindow())
	}

	clock.advance(40 * time.Millisecond)
	acks := make([]congestion.AckedPacket, 0, len(pending)-1)
	for _, p := range pending[:len(pending)-1] {
		acks = append(acks, congestion.AckedPacket{
			PacketNumber: p.pn,
			BytesAcked:   p.bytes,
			SentTime:     p.sentAt,
			ReceivedTime: clock.Now(),
		})
	}
	lost := []congestion.LostPacket{{PacketNumber: pending[len(pending)-1].pn, BytesLost: 1200}}

	s.OnCongestionEventEx(inFlight, clock.Now(), acks, lost)

	if s.GetCongestionWindow() < congestion.ByteCount(minCongestionWindowPackets)*1200 {
		t.Fatalf("cwnd dropped below floor after event: %d", s.GetCongestionWindow())
	}
	if s.Mode() == ModeProbeRtt {
		t.Logf("transitioned into PROBE_RTT (acceptable but unexpected for one-shot test)")
	}
}

func TestBBR2SenderSetMaxDatagramSize(t *testing.T) {
	s := NewBBR2Sender(DefaultClock{}, 1200, 0, false)
	s.SetMaxDatagramSize(1500)
	if s.GetCongestionWindow()%1500 != 0 && s.GetCongestionWindow() < 4*1500 {
		t.Fatalf("cwnd %d not consistent with new MSS 1500", s.GetCongestionWindow())
	}
}
