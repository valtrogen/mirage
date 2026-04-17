package bbr2

import (
	"testing"
	"time"

	"github.com/valtrogen/mirage/congestion"
)

func TestControllerSatisfiesInterface(t *testing.T) {
	var _ congestion.Controller = New(1200, 0)
}

func TestControllerNewDefaultsDatagramSize(t *testing.T) {
	c := New(0, 0)
	c.SetMaxDatagramSize(1500)
}

func TestControllerTimeUntilSendImmediate(t *testing.T) {
	c := New(1200, 0)
	if d := c.TimeUntilSend(time.Now()); d != 0 {
		t.Fatalf("idle TimeUntilSend = %v, want 0", d)
	}
}

func TestControllerOnCongestionEventDelegates(t *testing.T) {
	c := New(1200, 0)
	now := time.Now()

	c.OnPacketSent(now, 1, 1200, 0, true)
	c.OnCongestionEvent(now.Add(40*time.Millisecond), 1200,
		[]congestion.AckedPacket{{
			PacketNumber: 1,
			BytesAcked:   1200,
			SentTime:     now,
			ReceivedTime: now.Add(40 * time.Millisecond),
		}}, nil)

	if c.GetCongestionWindow() == 0 {
		t.Fatal("cwnd should remain non-zero after a clean ack")
	}
}

func TestControllerOnAppLimited(t *testing.T) {
	c := New(1200, 0)
	c.OnAppLimited(0)
	c.OnAppLimited(2400)
}

func TestControllerCanSendMatchesCwnd(t *testing.T) {
	c := New(1200, 0)
	cwnd := c.GetCongestionWindow()
	if !c.CanSend(cwnd - 1) {
		t.Fatal("should permit sending below cwnd")
	}
	if c.CanSend(cwnd) {
		t.Fatal("must block sending at cwnd")
	}
}
