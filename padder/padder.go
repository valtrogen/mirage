package padder

import (
	"crypto/rand"
	"errors"
	"io"
	"sync"
	"time"
)

// Policy controls when keepalive padding fires and how big each packet
// is. The defaults are tuned to be cheap enough to not register on
// bandwidth budgets and small enough to not look like a probe.
type Policy struct {
	// IdleAfter is the application-level inactivity required before
	// padding starts. Zero disables padding entirely.
	IdleAfter time.Duration

	// Interval is the gap between padding packets while idle.
	Interval time.Duration

	// MinSize and MaxSize bound the random per-packet payload length.
	// Set both to the same value for a fixed size.
	MinSize int
	MaxSize int

	// Source supplies randomness; nil means crypto/rand.
	Source io.Reader
}

// Default returns a sensible policy: padding kicks in after 5s of idle,
// fires every 2s, with payloads in [64, 256) bytes.
func Default() Policy {
	return Policy{
		IdleAfter: 5 * time.Second,
		Interval:  2 * time.Second,
		MinSize:   64,
		MaxSize:   256,
	}
}

// Padder schedules and emits keepalive packets when both:
//   - the application has been idle for at least Policy.IdleAfter, AND
//   - the BBR controller has signalled it is in ProbeRTT or otherwise
//     bandwidth-spare (Allow=true).
//
// Both gates are required: padding during throughput-sensitive phases
// would distort BBR's bandwidth estimate; padding during real busy
// traffic would be useless overhead.
type Padder struct {
	policy Policy

	mu          sync.Mutex
	lastApp     time.Time
	lastPadding time.Time
	bbrAllow    bool
}

// New returns a Padder governed by p. Construction does not start any
// goroutine; the integrator drives the padder by calling Tick on the
// outbound loop.
func New(p Policy) *Padder {
	if p.MinSize > p.MaxSize {
		p.MinSize, p.MaxSize = p.MaxSize, p.MinSize
	}
	if p.MinSize < 0 {
		p.MinSize = 0
	}
	if p.Source == nil {
		p.Source = rand.Reader
	}
	now := time.Now()
	return &Padder{policy: p, lastApp: now, lastPadding: now}
}

// AppActivity records that real application data flowed at t. This is
// the primary "we are not idle" signal.
func (p *Padder) AppActivity(t time.Time) {
	p.mu.Lock()
	if t.After(p.lastApp) {
		p.lastApp = t
	}
	p.mu.Unlock()
}

// SetBBRAllow toggles the BBR-side gate. The integrator should set
// this true when the controller enters ProbeRTT (or another phase
// where padding is harmless) and false otherwise.
func (p *Padder) SetBBRAllow(allow bool) {
	p.mu.Lock()
	p.bbrAllow = allow
	p.mu.Unlock()
}

// ErrPaddingDisabled is returned when Policy.IdleAfter is zero.
var ErrPaddingDisabled = errors.New("mirage/padder: padding disabled by policy")

// Tick reports whether a keepalive packet should be emitted now and,
// if so, returns the random payload to ship.  When no padding is due
// it returns (nil, nil).
func (p *Padder) Tick(now time.Time) ([]byte, error) {
	if p.policy.IdleAfter == 0 {
		return nil, nil
	}
	p.mu.Lock()
	idleEnough := now.Sub(p.lastApp) >= p.policy.IdleAfter
	intervalOK := now.Sub(p.lastPadding) >= p.policy.Interval
	bbrOK := p.bbrAllow
	p.mu.Unlock()

	if !(idleEnough && intervalOK && bbrOK) {
		return nil, nil
	}

	payload, err := p.makePayload()
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.lastPadding = now
	p.mu.Unlock()
	return payload, nil
}

func (p *Padder) makePayload() ([]byte, error) {
	size := p.policy.MinSize
	if span := p.policy.MaxSize - p.policy.MinSize; span > 0 {
		var b [2]byte
		if _, err := io.ReadFull(p.policy.Source, b[:]); err != nil {
			return nil, err
		}
		jitter := int(uint16(b[0])<<8|uint16(b[1])) % (span + 1)
		size += jitter
	}
	if size == 0 {
		return []byte{}, nil
	}
	out := make([]byte, size)
	if _, err := io.ReadFull(p.policy.Source, out); err != nil {
		return nil, err
	}
	return out, nil
}
