package client

import (
	"bytes"
	"testing"

	"github.com/valtrogen/mirage/transport"
)

func TestCIDPoolBootstrapAndCurrent(t *testing.T) {
	p := newCIDPool(8)
	if got := p.currentDCID(); got != nil {
		t.Fatalf("expected nil before bootstrap, got %x", got)
	}
	p.setBootstrap([]byte{1, 2, 3, 4})
	if got := p.currentDCID(); !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("currentDCID=%x", got)
	}
	// Second call must be a no-op.
	p.setBootstrap([]byte{9, 9, 9, 9})
	if got := p.currentDCID(); !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("setBootstrap mutated active: %x", got)
	}
}

func TestCIDPoolAddNewIgnoresDuplicates(t *testing.T) {
	p := newCIDPool(8)
	p.setBootstrap([]byte{0xAA})
	f := transport.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: []byte{0xBB}}
	if !p.addNew(f) {
		t.Fatal("first addNew should admit")
	}
	if p.addNew(f) {
		t.Fatal("duplicate seq must not be re-admitted")
	}
	_, idle, _ := p.stats()
	if idle != 1 {
		t.Fatalf("idle=%d want 1", idle)
	}
}

func TestCIDPoolAddNewHonorsRetirePriorTo(t *testing.T) {
	p := newCIDPool(8)
	p.setBootstrap([]byte{0xAA})
	// Issue seq 1, then seq 2 with retire_prior_to=2 (retires
	// the bootstrap and seq 1).
	p.addNew(transport.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: []byte{0xBB}})
	p.addNew(transport.NewConnectionIDFrame{
		SequenceNumber: 2, ConnectionID: []byte{0xCC}, RetirePriorTo: 2,
	})

	active, idle, pendingRetire := p.stats()
	if active != 2 {
		t.Fatalf("active seq=%d want 2", active)
	}
	if idle != 0 {
		t.Fatalf("idle=%d want 0", idle)
	}
	if pendingRetire != 2 {
		t.Fatalf("pendingRetire=%d want 2 (seq 0 + seq 1)", pendingRetire)
	}
	got := p.drainPendingRetire()
	if len(got) != 2 {
		t.Fatalf("drain=%v", got)
	}
}

func TestCIDPoolVoluntaryRotateSwapsActive(t *testing.T) {
	p := newCIDPool(8)
	p.setBootstrap([]byte{0xAA})
	p.addNew(transport.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: []byte{0xBB}})

	newCID, ok := p.voluntaryRotate()
	if !ok {
		t.Fatal("voluntaryRotate should succeed when idle is non-empty")
	}
	if !bytes.Equal(newCID, []byte{0xBB}) {
		t.Fatalf("newCID=%x want BB", newCID)
	}
	if !bytes.Equal(p.currentDCID(), []byte{0xBB}) {
		t.Fatalf("currentDCID after rotate=%x", p.currentDCID())
	}
	retire := p.drainPendingRetire()
	if len(retire) != 1 || retire[0] != 0 {
		t.Fatalf("expected RETIRE for seq 0, got %v", retire)
	}
}

func TestCIDPoolVoluntaryRotateNoIdle(t *testing.T) {
	p := newCIDPool(8)
	p.setBootstrap([]byte{0xAA})
	if _, ok := p.voluntaryRotate(); ok {
		t.Fatal("expected no-op rotate when idle empty")
	}
}

func TestCIDPoolEnforcesLimit(t *testing.T) {
	p := newCIDPool(3) // active + 2 idle
	p.setBootstrap([]byte{0xAA})
	for seq := uint64(1); seq <= 5; seq++ {
		p.addNew(transport.NewConnectionIDFrame{
			SequenceNumber: seq, ConnectionID: []byte{byte(seq)},
		})
	}
	_, idle, pendingRetire := p.stats()
	// active(seq=0) + idle(2) = 3 retained; the other 3 idle
	// entries must have been pushed onto pendingRetire.
	if idle != 2 {
		t.Fatalf("idle=%d want 2", idle)
	}
	if pendingRetire != 3 {
		t.Fatalf("pendingRetire=%d want 3 (oldest evicted)", pendingRetire)
	}
}
