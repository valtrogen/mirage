package behavior

import "time"

// ChromeH3 is the set of timing and sizing constants we line up with so
// that a mirage QUIC connection looks, on the wire, like a Chrome
// HTTP/3 connection.
//
// Values are taken from Chromium's net/quic defaults as of the 12x
// releases. They are deliberately read-only: changing one of these in
// production drifts the fingerprint and is the kind of mistake that
// gets a protocol classified.
type ChromeH3 struct {
	// PingInterval is the period between client-issued PING frames on
	// an otherwise-idle connection. Chrome uses ~30s.
	PingInterval time.Duration

	// MaxAckDelay is what we advertise in transport parameters. Chrome
	// advertises 25ms.
	MaxAckDelay time.Duration

	// AckDelayExponent is what we advertise in transport parameters.
	// Chrome uses 3.
	AckDelayExponent uint8

	// MaxIdleTimeout is the per-connection idle timeout we advertise.
	// Chrome uses 30s.
	MaxIdleTimeout time.Duration

	// MaxUDPPayloadSize is the largest UDP payload we advertise. Chrome
	// uses 1452 (a typical IPv4 path MTU minus QUIC headers).
	MaxUDPPayloadSize uint64

	// PMTUInitial is the conservative initial probe size.
	PMTUInitial uint16

	// PMTUSearchStep is the increment used by Chrome's DPLPMTUD search.
	PMTUSearchStep uint16

	// PMTUSearchInterval is the gap between successive PMTU probes.
	PMTUSearchInterval time.Duration

	// PMTUMaxProbes caps the number of PMTU probes per connection so
	// we do not stand out from Chrome's "probe a few times then stop"
	// behaviour.
	PMTUMaxProbes int

	// ActiveConnectionIDLimit is the value advertised in transport
	// parameters. Chrome uses 4.
	ActiveConnectionIDLimit uint64
}

// Default returns the canonical Chrome HTTP/3 profile mirage targets.
func Default() ChromeH3 {
	return ChromeH3{
		PingInterval:            30 * time.Second,
		MaxAckDelay:             25 * time.Millisecond,
		AckDelayExponent:        3,
		MaxIdleTimeout:          30 * time.Second,
		MaxUDPPayloadSize:       1452,
		PMTUInitial:             1252,
		PMTUSearchStep:          24,
		PMTUSearchInterval:      30 * time.Second,
		PMTUMaxProbes:           5,
		ActiveConnectionIDLimit: 4,
	}
}
