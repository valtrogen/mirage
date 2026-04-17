package padder

import (
	"bytes"
	"testing"
	"time"
)

func TestDisabledPolicyEmitsNothing(t *testing.T) {
	p := New(Policy{IdleAfter: 0})
	p.SetBBRAllow(true)
	got, err := p.Tick(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if got != nil {
		t.Fatalf("padding emitted while disabled: %x", got)
	}
}

func TestRequiresIdleAndBBRAllow(t *testing.T) {
	pol := Policy{IdleAfter: 10 * time.Millisecond, Interval: time.Millisecond, MinSize: 8, MaxSize: 8}
	p := New(pol)
	now := time.Now()

	if got, _ := p.Tick(now); got != nil {
		t.Fatal("not idle yet")
	}
	now = now.Add(20 * time.Millisecond)
	if got, _ := p.Tick(now); got != nil {
		t.Fatal("BBR gate closed")
	}
	p.SetBBRAllow(true)
	got, err := p.Tick(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 8 {
		t.Fatalf("unexpected size %d", len(got))
	}
}

func TestRespectsInterval(t *testing.T) {
	pol := Policy{IdleAfter: time.Millisecond, Interval: 50 * time.Millisecond, MinSize: 4, MaxSize: 4}
	p := New(pol)
	p.SetBBRAllow(true)
	now := time.Now().Add(time.Second)

	first, _ := p.Tick(now)
	if first == nil {
		t.Fatal("first tick should fire")
	}
	if again, _ := p.Tick(now.Add(10 * time.Millisecond)); again != nil {
		t.Fatal("second tick should be suppressed by Interval")
	}
	if again, _ := p.Tick(now.Add(60 * time.Millisecond)); again == nil {
		t.Fatal("third tick should fire after Interval elapsed")
	}
}

func TestAppActivityDelaysPadding(t *testing.T) {
	pol := Policy{IdleAfter: 50 * time.Millisecond, Interval: time.Millisecond, MinSize: 4, MaxSize: 4}
	p := New(pol)
	p.SetBBRAllow(true)
	now := time.Now()

	p.AppActivity(now.Add(40 * time.Millisecond))
	if got, _ := p.Tick(now.Add(60 * time.Millisecond)); got != nil {
		t.Fatal("activity 20ms ago: still inside IdleAfter window")
	}
	if got, _ := p.Tick(now.Add(120 * time.Millisecond)); got == nil {
		t.Fatal("80ms after activity: should pad")
	}
}

func TestSizeStaysInRange(t *testing.T) {
	pol := Policy{IdleAfter: time.Millisecond, Interval: time.Microsecond, MinSize: 32, MaxSize: 96}
	p := New(pol)
	p.SetBBRAllow(true)
	now := time.Now().Add(time.Second)
	for i := 0; i < 32; i++ {
		now = now.Add(time.Millisecond)
		got, err := p.Tick(now)
		if err != nil {
			t.Fatal(err)
		}
		if got == nil {
			t.Fatalf("iter %d: nil", i)
		}
		if len(got) < 32 || len(got) > 96 {
			t.Fatalf("iter %d: size %d out of range", i, len(got))
		}
	}
}

func TestDeterministicSourceProducesPayload(t *testing.T) {
	pol := Policy{
		IdleAfter: time.Millisecond,
		Interval:  time.Microsecond,
		MinSize:   8,
		MaxSize:   8,
		Source:    bytes.NewReader(bytes.Repeat([]byte{0xAB}, 64)),
	}
	p := New(pol)
	p.SetBBRAllow(true)
	got, err := p.Tick(time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0xAB}, 8)) {
		t.Fatalf("unexpected payload %x", got)
	}
}
