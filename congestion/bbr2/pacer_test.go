package bbr2

import (
	"testing"
	"time"

	"github.com/valtrogen/mirage/congestion"
)

func TestPacerInitialBudgetIsBurst(t *testing.T) {
	rate := 1 * MBytesPerSecond
	p := newPacer(func() Bandwidth { return rate }, 1200)

	got := p.Budget(time.Now())
	want := p.maxBurstSize()
	if got != want {
		t.Fatalf("initial budget = %d, want %d (burst)", got, want)
	}
	if got < 10*1200 {
		t.Fatalf("initial burst should cover at least %d bytes, got %d", 10*1200, got)
	}
}

func TestPacerBudgetReplenishesOverTime(t *testing.T) {
	rate := 1 * MBytesPerSecond
	p := newPacer(func() Bandwidth { return rate }, 1200)

	now := time.Now()
	p.SentPacket(now, 1200) // drain budget by one packet
	earlier := p.Budget(now)

	later := p.Budget(now.Add(10 * time.Millisecond))
	if later <= earlier {
		t.Fatalf("budget should grow with time, before=%d after=%d", earlier, later)
	}
}

func TestPacerTimeUntilSendZeroWhenBudgetSufficient(t *testing.T) {
	rate := 1 * MBytesPerSecond
	p := newPacer(func() Bandwidth { return rate }, 1200)

	if d := p.TimeUntilSend(); !d.IsZero() {
		t.Fatalf("TimeUntilSend with full burst = %v, want zero time", d)
	}
}

func TestPacerTimeUntilSendUsesPacingRateAfterDrain(t *testing.T) {
	rate := 1 * MBytesPerSecond
	p := newPacer(func() Bandwidth { return rate }, 1200)

	now := time.Now()
	for i := 0; i < maxBurstSizePackets+1; i++ {
		p.SentPacket(now.Add(time.Duration(i)*time.Microsecond), 1200)
	}

	at := p.TimeUntilSend()
	if at.IsZero() {
		t.Fatal("after burst drain, TimeUntilSend should return a non-zero deadline")
	}
	if at.Before(now) {
		t.Fatalf("deadline %v is before sent time %v", at, now)
	}
}

func TestPacerSetMaxDatagramSize(t *testing.T) {
	rate := 1 * MBytesPerSecond
	p := newPacer(func() Bandwidth { return rate }, 1200)

	p.SetMaxDatagramSize(2400)
	if p.maxDatagramSize != congestion.ByteCount(2400) {
		t.Fatalf("maxDatagramSize = %d, want 2400", p.maxDatagramSize)
	}
}
