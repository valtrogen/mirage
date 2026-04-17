package client

import (
	"testing"
	"time"

	"github.com/valtrogen/mirage/transport"
)

// TestConnHandleNewConnectionIDFeedsPool drives the same code path as
// the real receive loop. The frame is delivered while the connection
// is "in 1-RTT" (we install a non-nil cidPool with a bootstrap entry
// up front) and we verify that a subsequent NEW_CONNECTION_ID with
// retire_prior_to=0 is admitted but does not yet rotate, while a
// matching maybeRotateCID call after the rotation interval flips the
// active CID and queues a RETIRE for seq 0.
func TestConnHandleNewConnectionIDFeedsPool(t *testing.T) {
	c := &Conn{cids: newCIDPool(8)}
	c.cids.setBootstrap([]byte{0xAA, 0xBB, 0xCC, 0xDD})

	c.handleNewConnectionID(transport.NewConnectionIDFrame{
		SequenceNumber: 1,
		ConnectionID:   []byte{0x11, 0x22, 0x33, 0x44},
	})

	if got := c.sendDCID(); string(got) != string([]byte{0xAA, 0xBB, 0xCC, 0xDD}) {
		t.Fatalf("active DCID changed without rotation: %x", got)
	}

	// Force-rotate as if the timer had fired.
	c.lastCIDRotate = time.Now().Add(-1 * time.Hour)
	c.maybeRotateCID(time.Now())

	if got := c.sendDCID(); string(got) != string([]byte{0x11, 0x22, 0x33, 0x44}) {
		t.Fatalf("active DCID after rotation: %x", got)
	}
	retire := c.cids.drainPendingRetire()
	if len(retire) != 1 || retire[0] != 0 {
		t.Fatalf("expected RETIRE for bootstrap seq 0, got %v", retire)
	}
}

// TestConnMaybeRotateCIDRespectsInterval verifies the rotation only
// fires once per Behavior.CIDRotateInterval window. Two back-to-back
// calls must result in exactly one rotation.
func TestConnMaybeRotateCIDRespectsInterval(t *testing.T) {
	c := &Conn{cfg: &Config{}, cids: newCIDPool(8)}
	c.cids.setBootstrap([]byte{0x01})
	c.cids.addNew(transport.NewConnectionIDFrame{SequenceNumber: 1, ConnectionID: []byte{0x02}})
	c.cids.addNew(transport.NewConnectionIDFrame{SequenceNumber: 2, ConnectionID: []byte{0x03}})

	c.lastCIDRotate = time.Now().Add(-1 * time.Hour)
	c.maybeRotateCID(time.Now())
	first := c.sendDCID()
	c.maybeRotateCID(time.Now())
	second := c.sendDCID()

	if string(first) != string(second) {
		t.Fatalf("rotation fired twice within one interval: first=%x second=%x", first, second)
	}
}
