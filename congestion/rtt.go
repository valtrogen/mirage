package congestion

import (
	"sync"
	"time"
)

// RTTStats tracks min/latest/smoothed/mean-deviation RTT for one
// connection, following the formulas in RFC 9002 §5. It is safe for
// concurrent use; the receiver loop calls UpdateRTT and the sender
// loop reads SmoothedRTT / MinRTT / PTO.
type RTTStats struct {
	mu sync.RWMutex

	hasMeasurement bool

	minRTT        time.Duration
	latestRTT     time.Duration
	smoothedRTT   time.Duration
	meanDeviation time.Duration

	maxAckDelay time.Duration
}

// NewRTTStats returns an RTTStats with no samples and the default
// maximum ack delay (25 ms, RFC 9000 §18.2).
func NewRTTStats() *RTTStats {
	return &RTTStats{maxAckDelay: 25 * time.Millisecond}
}

// SetMaxAckDelay updates the peer-advertised max_ack_delay. It is used
// by PTO and by BBRv2's RTT-with-ack-delay subtraction logic.
func (r *RTTStats) SetMaxAckDelay(d time.Duration) {
	if d < 0 {
		d = 0
	}
	r.mu.Lock()
	r.maxAckDelay = d
	r.mu.Unlock()
}

// UpdateRTT folds one new RTT sample into the smoothed estimator.
// sendDelta is the wall time between sending the packet and observing
// the ACK; ackDelay is the peer-reported processing delay (per QUIC's
// ACK_DELAY field). Both default to "no info" when zero.
//
// Per RFC 9002:
//   - latest_rtt = sendDelta
//   - if first sample: smoothed = latest, mean_dev = latest/2
//   - else if (latest - ack_delay) is positive and ≥ min_rtt, use
//     adjusted RTT for smoothing
//   - smoothed = 7/8*smoothed + 1/8*adjusted
//   - mean_dev = 3/4*mean_dev + 1/4*|smoothed - adjusted|
func (r *RTTStats) UpdateRTT(sendDelta, ackDelay time.Duration) {
	if sendDelta <= 0 {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	r.latestRTT = sendDelta
	if !r.hasMeasurement || sendDelta < r.minRTT {
		r.minRTT = sendDelta
	}

	adjusted := sendDelta
	if ackDelay > 0 && sendDelta-ackDelay >= r.minRTT {
		adjusted = sendDelta - ackDelay
	}

	if !r.hasMeasurement {
		r.smoothedRTT = adjusted
		r.meanDeviation = adjusted / 2
		r.hasMeasurement = true
		return
	}

	var diff time.Duration
	if r.smoothedRTT > adjusted {
		diff = r.smoothedRTT - adjusted
	} else {
		diff = adjusted - r.smoothedRTT
	}
	r.meanDeviation = (3*r.meanDeviation + diff) / 4
	r.smoothedRTT = (7*r.smoothedRTT + adjusted) / 8
}

// MinRTT returns the smallest RTT sample observed, or 0 before any
// sample has been folded in.
func (r *RTTStats) MinRTT() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.minRTT
}

// SmoothedRTT returns the EWMA smoothed RTT, or 0 before any sample.
func (r *RTTStats) SmoothedRTT() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.smoothedRTT
}

// LatestRTT returns the most recent sample, or 0 before any sample.
func (r *RTTStats) LatestRTT() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.latestRTT
}

// MeanDeviation returns the smoothed RTT variation, or 0 before any
// sample.
func (r *RTTStats) MeanDeviation() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.meanDeviation
}

// MaxAckDelay returns the peer-advertised max_ack_delay.
func (r *RTTStats) MaxAckDelay() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.maxAckDelay
}

// PTO returns the probe timeout per RFC 9002 §6.2.1:
//
//	smoothed_rtt + max(4*rttvar, kGranularity) + max_ack_delay
//
// kGranularity is 1 ms. Returns 0 before the first measurement.
func (r *RTTStats) PTO() time.Duration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if !r.hasMeasurement {
		return 0
	}
	const kGranularity = time.Millisecond
	rttvar := 4 * r.meanDeviation
	if rttvar < kGranularity {
		rttvar = kGranularity
	}
	return r.smoothedRTT + rttvar + r.maxAckDelay
}

// HasMeasurement reports whether at least one sample has been
// observed.
func (r *RTTStats) HasMeasurement() bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hasMeasurement
}
