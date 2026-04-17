// Adapter that exposes BBR2Sender through mirage's congestion.Controller
// interface. The sender itself models its scheduling decisions as
// absolute wall-clock times (cloudflare/quiche convention); mirage
// expects relative durations, so the translation lives here rather than
// inside the algorithm.
//
// This file is also where the boundary mutex lives: BBR2Sender keeps
// internal maps and slices that were never designed for concurrent
// access, but the mirage client necessarily drives the controller from
// two goroutines (the sender loop calls OnPacketSent / CanSend; the
// receiver loop calls OnCongestionEvent / OnAppLimited). Wrapping every
// public method with one mutex turns the BBR2Sender into a thread-safe
// black box without touching the ported quiche code.

package bbr2

import (
	"sync"
	"time"

	"github.com/valtrogen/mirage/congestion"
)

// Controller wraps a *BBR2Sender so it satisfies the
// congestion.Controller interface used by the mirage client. All
// methods are safe to call from concurrent goroutines.
type Controller struct {
	mu sync.Mutex
	s  *BBR2Sender
}

// New returns a BBR2-backed congestion controller wired with the
// supplied datagram size and initial cwnd (in bytes; pass 0 for the
// default 10 packets). The clock defaults to the system wall clock.
func New(maxDatagramSize, initialCwnd congestion.ByteCount) *Controller {
	return NewWithClock(DefaultClock{}, maxDatagramSize, initialCwnd)
}

// NewWithClock is the test-friendly constructor that lets callers
// inject a Clock implementation (used by the BBR2 unit tests to walk a
// scripted timeline).
func NewWithClock(clock Clock, maxDatagramSize, initialCwnd congestion.ByteCount) *Controller {
	if maxDatagramSize == 0 {
		maxDatagramSize = 1200
	}
	return &Controller{
		s: NewBBR2Sender(clock, maxDatagramSize, initialCwnd, false),
	}
}

// OnPacketSent implements congestion.Controller. The BBR2 sender
// expects bytesInFlight *before* this packet, matching mirage's
// contract.
func (c *Controller) OnPacketSent(now time.Time, pn congestion.PacketNumber, bytes congestion.ByteCount,
	bytesInFlight congestion.ByteCount, retransmittable bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.s.OnPacketSent(now, bytesInFlight, pn, bytes, retransmittable)
}

// OnCongestionEvent implements congestion.Controller by funnelling
// the batch into BBR2's combined ack/loss handler.
func (c *Controller) OnCongestionEvent(now time.Time, priorBytesInFlight congestion.ByteCount,
	acked []congestion.AckedPacket, lost []congestion.LostPacket) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.s.OnCongestionEventEx(priorBytesInFlight, now, acked, lost)
}

// OnAppLimited implements congestion.Controller.
func (c *Controller) OnAppLimited(bytesInFlight congestion.ByteCount) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.s.OnAppLimited(bytesInFlight)
}

// CanSend implements congestion.Controller.
func (c *Controller) CanSend(bytesInFlight congestion.ByteCount) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.s.CanSend(bytesInFlight)
}

// TimeUntilSend implements congestion.Controller. It returns the
// pacer's idle time before the next packet is allowed on the wire.
// The cwnd-block decision is the caller's responsibility (via
// CanSend); we only query the pacer here.
func (c *Controller) TimeUntilSend(now time.Time) time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	at := c.s.pacer.TimeUntilSend()
	if at.IsZero() {
		return 0
	}
	if !at.After(now) {
		return 0
	}
	return at.Sub(now)
}

// GetCongestionWindow implements congestion.Controller.
func (c *Controller) GetCongestionWindow() congestion.ByteCount {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.s.GetCongestionWindow()
}

// PacingRate implements congestion.Controller.
func (c *Controller) PacingRate() congestion.Bandwidth {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.s.PacingRate()
}

// SetMaxDatagramSize implements congestion.Controller.
func (c *Controller) SetMaxDatagramSize(size congestion.ByteCount) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.s.SetMaxDatagramSize(size)
}

// InProbeRTT reports whether the sender is currently in the ProbeRTT
// phase. The mirage padder uses this as a gate: padding is only
// injected during ProbeRTT (or other low-throughput states) so it
// does not distort BBR's bandwidth estimate.
func (c *Controller) InProbeRTT() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.s.mode == ModeProbeRtt
}

// Compile-time check that *Controller honours the public interface.
var _ congestion.Controller = (*Controller)(nil)
