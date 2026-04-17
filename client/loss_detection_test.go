package client

import (
	"testing"
	"time"

	"github.com/valtrogen/mirage/congestion"
)

// newLossTestConn builds a bare Conn populated with just the fields
// detectLossesLocked needs, so the loss detector can be exercised in
// isolation from the handshake / network plumbing.
func newLossTestConn() *Conn {
	c := &Conn{
		sent:      make(map[uint64]*sentPacket),
		sentTimes: make(map[uint64]time.Time),
		rtt:       congestion.NewRTTStats(),
	}
	c.rtt.UpdateRTT(40*time.Millisecond, 0)
	return c
}

func putSent(c *Conn, pn uint64, sentAt time.Time, size congestion.ByteCount) {
	c.sent[pn] = &sentPacket{pn: pn, sentAt: sentAt, size: size}
	c.sentTimes[pn] = sentAt
	c.bytesInFlight += size
}

// TestDetectLossesPacketThreshold verifies the §6.1.1 rule: a packet
// is declared lost once kPacketThreshold (=3) higher-numbered packets
// have been acked.
func TestDetectLossesPacketThreshold(t *testing.T) {
	c := newLossTestConn()
	now := time.Now()
	for pn := uint64(1); pn <= 6; pn++ {
		putSent(c, pn, now, 1200)
	}

	// Largest acked = 5 → packets <= 5-3 = 2 should be lost.
	c.largestAckedPN = 5
	c.largestAckedSentAt = now
	c.hasLargestAcked = true

	c.sentMu.Lock()
	lost := c.detectLossesLocked(now)
	c.sentMu.Unlock()

	if len(lost) != 2 {
		t.Fatalf("expected 2 losses (pn 1, 2), got %d: %+v", len(lost), lost)
	}
	want := map[congestion.PacketNumber]bool{1: true, 2: true}
	for _, l := range lost {
		if !want[l.PacketNumber] {
			t.Fatalf("unexpected loss pn=%d", l.PacketNumber)
		}
	}
	if _, ok := c.sent[1]; ok {
		t.Fatal("pn 1 should have been removed from sent")
	}
	if _, ok := c.sent[3]; !ok {
		t.Fatal("pn 3 should still be in sent (only one ahead, not enough to trigger threshold)")
	}
	if c.bytesInFlight != 4*1200 {
		t.Fatalf("bytesInFlight = %d, want %d", c.bytesInFlight, 4*1200)
	}
	if got := len(c.lostQueue); got != 2 {
		t.Fatalf("lostQueue len = %d, want 2", got)
	}
}

// TestDetectLossesTimeThreshold verifies the §6.1.2 rule: a packet
// older than 9/8 × max(SRTT, latest_RTT) is declared lost even if
// fewer than kPacketThreshold packets have been acked above it.
func TestDetectLossesTimeThreshold(t *testing.T) {
	c := newLossTestConn() // SRTT = 40ms, so lossDelay = 45ms
	now := time.Now()
	putSent(c, 10, now.Add(-100*time.Millisecond), 1200) // older than 45ms
	putSent(c, 11, now, 1200)
	putSent(c, 12, now, 1200) // largest acked

	c.largestAckedPN = 12
	c.largestAckedSentAt = now
	c.hasLargestAcked = true

	c.sentMu.Lock()
	lost := c.detectLossesLocked(now)
	c.sentMu.Unlock()

	if len(lost) != 1 || lost[0].PacketNumber != 10 {
		t.Fatalf("expected pn 10 lost, got %+v", lost)
	}
	if _, ok := c.sent[10]; ok {
		t.Fatal("pn 10 should be removed")
	}
	if _, ok := c.sent[11]; !ok {
		t.Fatal("pn 11 should remain (sent now)")
	}
}

// TestDetectLossesNoFalsePositives ensures the detector leaves the
// in-flight set untouched when nothing meets either rule.
func TestDetectLossesNoFalsePositives(t *testing.T) {
	c := newLossTestConn()
	now := time.Now()
	putSent(c, 100, now, 1200)
	putSent(c, 101, now, 1200) // largest acked

	c.largestAckedPN = 101
	c.largestAckedSentAt = now
	c.hasLargestAcked = true

	c.sentMu.Lock()
	lost := c.detectLossesLocked(now)
	c.sentMu.Unlock()

	if len(lost) != 0 {
		t.Fatalf("expected no losses, got %+v", lost)
	}
	if c.bytesInFlight != 2*1200 {
		t.Fatalf("bytesInFlight = %d, want %d", c.bytesInFlight, 2*1200)
	}
	if len(c.lostQueue) != 0 {
		t.Fatal("lostQueue should be empty")
	}
}

// TestDetectLossesIgnoresHigherThanLargest verifies that packets above
// the largest-acked horizon are never declared lost: their fate is
// pending the next ack.
func TestDetectLossesIgnoresHigherThanLargest(t *testing.T) {
	c := newLossTestConn()
	now := time.Now()
	putSent(c, 10, now.Add(-time.Second), 1200) // very old, ahead of largest
	c.largestAckedPN = 5
	c.largestAckedSentAt = now
	c.hasLargestAcked = true

	c.sentMu.Lock()
	lost := c.detectLossesLocked(now)
	c.sentMu.Unlock()

	if len(lost) != 0 {
		t.Fatalf("packets > largestAcked must not be declared lost: %+v", lost)
	}
	if _, ok := c.sent[10]; !ok {
		t.Fatal("pn 10 should still be in sent")
	}
}
