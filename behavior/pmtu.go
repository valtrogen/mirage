package behavior

import "time"

// PMTUSearch is a tiny step-up DPLPMTUD-style probe scheduler matching
// Chrome's defaults: start at PMTUInitial, step up by PMTUSearchStep
// every PMTUSearchInterval, give up after PMTUMaxProbes attempts. A
// successful probe (Confirmed) becomes the new floor for subsequent
// probes.
type PMTUSearch struct {
	cfg ChromeH3

	current   uint16
	probes    int
	lastProbe time.Time
}

// NewPMTUSearch returns a search initialised to cfg.PMTUInitial.
func NewPMTUSearch(cfg ChromeH3) *PMTUSearch {
	return &PMTUSearch{cfg: cfg, current: cfg.PMTUInitial}
}

// Current returns the largest size known to work.
func (s *PMTUSearch) Current() uint16 { return s.current }

// NextProbeSize returns the next size we should probe with, or 0 when
// the search has stopped (cap reached or max probe count hit).
func (s *PMTUSearch) NextProbeSize() uint16 {
	if s.probes >= s.cfg.PMTUMaxProbes {
		return 0
	}
	candidate := uint32(s.current) + uint32(s.cfg.PMTUSearchStep)
	if candidate > uint32(s.cfg.MaxUDPPayloadSize) {
		return 0
	}
	return uint16(candidate)
}

// ShouldProbe reports whether enough time has passed since the last
// probe attempt to fire another.
func (s *PMTUSearch) ShouldProbe(now time.Time) bool {
	if s.NextProbeSize() == 0 {
		return false
	}
	if s.lastProbe.IsZero() {
		return true
	}
	return now.Sub(s.lastProbe) >= s.cfg.PMTUSearchInterval
}

// Sent records that a probe of the given size has been transmitted.
func (s *PMTUSearch) Sent(size uint16, at time.Time) {
	s.probes++
	s.lastProbe = at
	_ = size
}

// Confirmed records that a probe of the given size made it through
// (acknowledged or otherwise positively echoed). Sizes smaller than
// the current floor are ignored.
func (s *PMTUSearch) Confirmed(size uint16) {
	if size > s.current {
		s.current = size
	}
}
