package client

import "github.com/valtrogen/mirage/recycle"

// TriggerRecycleHintForTest drives Pool.onRecycleHint without going
// through the real wire. It exists so external integration tests can
// verify the three-stage handoff state machine without requiring the
// server to actually emit a control frame.
func (p *Pool) TriggerRecycleHintForTest(old *Conn, h recycle.Hint) {
	p.onRecycleHint(old, h)
}
