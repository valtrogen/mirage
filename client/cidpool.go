package client

import (
	"sync"

	"github.com/valtrogen/mirage/transport"
)

// cidEntry is one destination connection ID known to the client. seq
// is the sequence number the peer used in the NEW_CONNECTION_ID frame
// that introduced it (or 0 for the bootstrap CID adopted from the
// server's first Initial packet, per RFC 9000 §5.1.1).
type cidEntry struct {
	seq uint64
	cid []byte
}

// cidPool tracks the set of destination connection IDs the peer has
// authorised the client to send to, and the sequence number of the
// one currently in use. It also batches RETIRE_CONNECTION_ID frames
// the senderLoop will emit on the next iteration.
//
// The bootstrap entry (seq 0) is admitted by setBootstrap, called from
// adoptServerDCID. NEW_CONNECTION_ID frames feed addNew, which honours
// retire_prior_to by retiring any older entries (including the active
// one if it falls below the threshold). voluntaryRotate is called by
// the senderLoop on a timer to swap to a fresh CID even when the peer
// has not asked us to.
//
// The pool retains at most ActiveConnectionIDLimit entries (the value
// the client advertises in its transport parameters); excess inbound
// CIDs are silently retired so an attacker cannot exhaust client
// memory by flooding NEW_CONNECTION_ID frames.
type cidPool struct {
	mu sync.Mutex

	active cidEntry
	idle   []cidEntry
	limit  int

	// pendingRetire holds peer sequence numbers we still owe a
	// RETIRE_CONNECTION_ID for. flushApp drains it on every send.
	pendingRetire []uint64
}

// newCIDPool returns an empty pool with the given retention limit.
// The limit applies to active + idle combined; a value of zero or
// negative collapses to 2 so we always retain at least one spare for
// rotation.
func newCIDPool(limit int) *cidPool {
	if limit < 2 {
		limit = 2
	}
	return &cidPool{limit: limit}
}

// setBootstrap installs the initial DCID (sequence 0). It is a no-op
// if called more than once; the bootstrap CID never changes after the
// server's first Initial.
func (p *cidPool) setBootstrap(cid []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active.cid != nil {
		return
	}
	p.active = cidEntry{seq: 0, cid: append([]byte(nil), cid...)}
}

// active returns a copy of the currently-active DCID. If no DCID has
// been installed yet (pre-handshake) the result is nil.
func (p *cidPool) currentDCID() []byte {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.active.cid == nil {
		return nil
	}
	return append([]byte(nil), p.active.cid...)
}

// addNew records one peer-issued NEW_CONNECTION_ID. Returns the
// number of pool entries (active+idle) after admission, useful for
// metrics. retirePriorTo is honoured: any entry with seq < retire is
// dropped and queued for RETIRE_CONNECTION_ID; if the active entry
// itself is below retirePriorTo, the next available idle entry is
// promoted before the old one is queued.
func (p *cidPool) addNew(f transport.NewConnectionIDFrame) (admitted bool) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// Reject duplicates: the spec allows the peer to retransmit
	// NEW_CONNECTION_ID and we must not double-count or rotate twice.
	if p.active.cid != nil && p.active.seq == f.SequenceNumber {
		return false
	}
	for _, e := range p.idle {
		if e.seq == f.SequenceNumber {
			return false
		}
	}

	p.idle = append(p.idle, cidEntry{
		seq: f.SequenceNumber,
		cid: append([]byte(nil), f.ConnectionID...),
	})

	// Honour retire_prior_to: drop any entries (active or idle)
	// strictly below the threshold.
	if f.RetirePriorTo > 0 {
		// Promote a replacement if the active entry is being retired.
		if p.active.cid != nil && p.active.seq < f.RetirePriorTo {
			p.pendingRetire = append(p.pendingRetire, p.active.seq)
			p.active = cidEntry{}
		}
		// Filter idle, retiring those below the threshold and
		// promoting the smallest survivor to active if needed.
		surv := p.idle[:0]
		for _, e := range p.idle {
			if e.seq < f.RetirePriorTo {
				p.pendingRetire = append(p.pendingRetire, e.seq)
				continue
			}
			surv = append(surv, e)
		}
		p.idle = surv
		if p.active.cid == nil && len(p.idle) > 0 {
			p.active = p.idle[0]
			p.idle = p.idle[1:]
		}
	}

	// Bound retention. Retire the lowest-seq idle entries first.
	for len(p.idle)+1 > p.limit {
		victim := p.idle[0]
		p.idle = p.idle[1:]
		p.pendingRetire = append(p.pendingRetire, victim.seq)
	}
	return true
}

// voluntaryRotate promotes the oldest idle entry to active and
// queues the previous active entry for RETIRE_CONNECTION_ID. It
// returns the new active CID, or nil with rotated=false if no idle
// entry was available.
func (p *cidPool) voluntaryRotate() (newCID []byte, rotated bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.idle) == 0 || p.active.cid == nil {
		return nil, false
	}
	old := p.active
	p.active = p.idle[0]
	p.idle = p.idle[1:]
	p.pendingRetire = append(p.pendingRetire, old.seq)
	return append([]byte(nil), p.active.cid...), true
}

// drainPendingRetire returns and clears any sequence numbers whose
// RETIRE_CONNECTION_ID frames have not yet been sent.
func (p *cidPool) drainPendingRetire() []uint64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.pendingRetire) == 0 {
		return nil
	}
	out := append([]uint64(nil), p.pendingRetire...)
	p.pendingRetire = p.pendingRetire[:0]
	return out
}

// stats reports counts for tests / metrics.
func (p *cidPool) stats() (activeSeq uint64, idleCount int, pendingRetireCount int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active.seq, len(p.idle), len(p.pendingRetire)
}
