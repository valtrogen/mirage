package client

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valtrogen/mirage/recycle"
)

// PoolConfig configures a Pool.
type PoolConfig struct {
	// Addr is the "host:port" passed to Dial.
	Addr string

	// Config is the mirage client configuration used for every dial
	// the pool issues. The pool overrides Config.OnRecycleHint with
	// its own callback; any value supplied by the caller is silently
	// replaced.
	Config Config

	// DrainGrace is the maximum time the pool keeps an old connection
	// alive after the server signals recycling. Streams already
	// running on that connection continue to flow; new streams always
	// land on the fresh connection. When the grace expires the old
	// connection is closed regardless of in-flight traffic. Zero uses
	// recycle.DefaultHandoffWindow (30s).
	DrainGrace time.Duration

	// DialTimeout caps each dial attempt. Zero uses 30s.
	DialTimeout time.Duration

	// Logger receives operational events. nil installs a discard logger.
	Logger *slog.Logger
}

// Pool maintains a single active mirage connection and seamlessly
// rolls it forward when the server emits a CONNECTION_RECYCLE_HINT
// frame.
//
// Three-stage handoff:
//
//  1. Server sends a hint frame on the control stream of the active
//     connection.
//  2. The pool dials a fresh connection and atomically promotes it to
//     active. Subsequent OpenStream calls land on the new connection.
//  3. The old connection is parked in "draining" with a deadline of
//     min(hint.HandoffWindow, DrainGrace) from now. When the deadline
//     fires the pool forces it closed regardless of in-flight streams.
//
// Pool is safe for concurrent use.
type Pool struct {
	cfg PoolConfig

	// dialFn is the seam tests use to swap out the real client.Dial.
	// Production code leaves it nil and gets dialOne via the standard
	// client.Dial path.
	dialFn func(ctx context.Context) (*Conn, error)

	mu     sync.Mutex
	active *Conn
	closed atomic.Bool

	rotateOnce sync.Mutex // serialises rotation handlers

	drainWG sync.WaitGroup
	stopCh  chan struct{}
}

// NewPool returns a Pool that has not yet dialed. The first call to
// Active or OpenStream triggers the initial dial.
func NewPool(cfg PoolConfig) (*Pool, error) {
	if cfg.Addr == "" {
		return nil, errors.New("mirage/client: PoolConfig.Addr is empty")
	}
	if err := cfg.Config.Validate(); err != nil {
		return nil, err
	}
	if cfg.DrainGrace <= 0 {
		cfg.DrainGrace = recycle.DefaultHandoffWindow
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 30 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	return &Pool{cfg: cfg, stopCh: make(chan struct{})}, nil
}

// Active returns the currently active connection, dialing on demand.
// If the previously-active connection has died and no replacement
// exists yet, Active dials a fresh one.
func (p *Pool) Active(ctx context.Context) (*Conn, error) {
	if p.closed.Load() {
		return nil, errors.New("mirage/client: Pool closed")
	}
	p.mu.Lock()
	if p.active != nil && !p.active.closed.Load() {
		c := p.active
		p.mu.Unlock()
		return c, nil
	}
	p.mu.Unlock()
	return p.dialAndSwap(ctx, nil)
}

// OpenStream is a convenience wrapper that opens a stream on the
// currently active connection.
func (p *Pool) OpenStream(ctx context.Context) (*Stream, error) {
	c, err := p.Active(ctx)
	if err != nil {
		return nil, err
	}
	return c.OpenStream(ctx)
}

// Close cancels every drain timer, closes the active connection, and
// blocks until all draining connections have finished. Subsequent
// calls are no-ops.
func (p *Pool) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(p.stopCh)
	p.mu.Lock()
	active := p.active
	p.active = nil
	p.mu.Unlock()
	if active != nil {
		_ = active.Close()
	}
	p.drainWG.Wait()
	return nil
}

// dialAndSwap dials a fresh connection and, when prev is nil or still
// the active one, promotes it to active. Returns the new connection.
//
// When prev is non-nil and is no longer active (some other goroutine
// already rotated past it), the new connection is closed and the
// current active is returned instead.
func (p *Pool) dialAndSwap(ctx context.Context, prev *Conn) (*Conn, error) {
	dialCtx, cancel := context.WithTimeout(ctx, p.cfg.DialTimeout)
	defer cancel()
	dial := p.dialFn
	if dial == nil {
		dial = p.dialOne
	}
	newConn, err := dial(dialCtx)
	if err != nil {
		return nil, err
	}
	p.mu.Lock()
	cur := p.active
	if prev != nil && cur != nil && cur != prev {
		// Lost the race; some other rotate beat us.
		p.mu.Unlock()
		_ = newConn.Close()
		return cur, nil
	}
	p.active = newConn
	p.mu.Unlock()
	return newConn, nil
}

// dialOne dials a single mirage connection and wires its
// OnRecycleHint callback back into the pool. The callback uses an
// atomic pointer so it can resolve to the connection it was installed
// on without a goroutine-startup race.
func (p *Pool) dialOne(ctx context.Context) (*Conn, error) {
	cfg := p.cfg.Config
	var holder atomic.Pointer[Conn]
	cfg.OnRecycleHint = func(h recycle.Hint) {
		c := holder.Load()
		if c == nil {
			return
		}
		p.onRecycleHint(c, h)
	}
	c, err := Dial(ctx, p.cfg.Addr, &cfg)
	if err != nil {
		return nil, err
	}
	holder.Store(c)
	return c, nil
}

// onRecycleHint runs the three-stage handoff on a background
// goroutine. It is called at most once per connection because the
// server is contractually expected to send the hint exactly once.
func (p *Pool) onRecycleHint(old *Conn, h recycle.Hint) {
	go func() {
		// Serialise concurrent hints (defensive: the spec says one,
		// the wire might disagree).
		p.rotateOnce.Lock()
		defer p.rotateOnce.Unlock()

		grace := h.HandoffWindow
		if grace <= 0 || grace > p.cfg.DrainGrace {
			grace = p.cfg.DrainGrace
		}

		ctx, cancel := context.WithTimeout(context.Background(), p.cfg.DialTimeout)
		defer cancel()
		newConn, err := p.dialAndSwap(ctx, old)
		if err != nil {
			p.cfg.Logger.Warn("mirage/client: pool dial during recycle failed",
				slog.String("err", err.Error()))
			return
		}
		if newConn == old {
			// dialAndSwap returned the existing active; nothing to drain.
			return
		}

		p.drainWG.Add(1)
		go p.drainCloser(old, grace)
	}()
}

// drainCloser parks old until grace elapses or the pool shuts down,
// then closes it. In-flight streams continue to operate during the
// grace window; new traffic has already migrated to the active conn.
func (p *Pool) drainCloser(old *Conn, grace time.Duration) {
	defer p.drainWG.Done()
	timer := time.NewTimer(grace)
	defer timer.Stop()
	select {
	case <-timer.C:
		p.cfg.Logger.Info("mirage/client: pool draining old conn after grace",
			slog.Duration("grace", grace))
	case <-p.stopCh:
	}
	_ = old.Close()
}
