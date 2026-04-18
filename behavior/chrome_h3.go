package behavior

import (
	"time"

	"github.com/quic-go/quic-go"
)

// ChromeH3 is the set of timing, sizing, and flow-control constants we
// align with so that a mirage QUIC connection looks, on the wire, like a
// Chrome HTTP/3 connection.
//
// Values are taken from Chromium's net/quic defaults as of the 13x
// release stream and from packet captures of real Chrome HTTP/3 traffic.
// They are deliberately read-only: changing one of these in production
// drifts the fingerprint and is the kind of mistake that gets a protocol
// classified.
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

	// HandshakeIdleTimeout caps the time a half-open handshake survives
	// without progress. Chrome's effective value is ~10s.
	HandshakeIdleTimeout time.Duration

	// MaxUDPPayloadSize is the largest UDP payload we advertise. Chrome
	// uses 1452 (a typical IPv4 path MTU minus QUIC headers).
	MaxUDPPayloadSize uint64

	// PMTUInitial is the conservative initial probe size. Doubles as
	// quic.Config.InitialPacketSize on the server.
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
	// parameters. Real Chrome H3 advertises 8.
	ActiveConnectionIDLimit uint64

	// InitialMaxData is the initial connection-level receive credit
	// advertised to the peer (RFC 9000 §4.1). Chrome uses 15 MiB.
	InitialMaxData uint64

	// InitialMaxStreamDataBidiLocal is the initial per-stream receive
	// credit for streams the local peer initiates. Chrome uses 6 MiB.
	InitialMaxStreamDataBidiLocal uint64

	// InitialMaxStreamDataBidiRemote is the same for peer-initiated
	// streams. Chrome uses 6 MiB.
	InitialMaxStreamDataBidiRemote uint64

	// InitialMaxStreamDataUni is the initial credit for unidirectional
	// streams. Chrome uses 6 MiB.
	InitialMaxStreamDataUni uint64

	// InitialMaxStreamsBidi is the maximum number of concurrent
	// bidirectional streams the peer may open. Chrome uses 100.
	InitialMaxStreamsBidi uint64

	// InitialMaxStreamsUni is the maximum number of concurrent
	// unidirectional streams the peer may open. Chrome uses 100.
	InitialMaxStreamsUni uint64

	// MaxStreamReceiveWindow is the auto-tune ceiling for per-stream
	// receive windows. quic-go uses this on the server.
	MaxStreamReceiveWindow uint64

	// MaxConnectionReceiveWindow is the auto-tune ceiling for the
	// connection-level receive window.
	MaxConnectionReceiveWindow uint64

	// CIDRotateInterval is the period between voluntary destination
	// connection ID rotations performed by the client. A long-lived
	// connection that keeps the same DCID exposes a packet-capture
	// fingerprint distinguishable from real Chrome, which rotates
	// CIDs on a similar cadence to its NEW_CONNECTION_ID issuance.
	// Zero disables voluntary rotation; the client still honours
	// peer-issued retire_prior_to in NEW_CONNECTION_ID frames.
	CIDRotateInterval time.Duration
}

// Default returns the canonical Chrome HTTP/3 profile mirage targets.
func Default() ChromeH3 {
	return ChromeH3{
		PingInterval:                   30 * time.Second,
		MaxAckDelay:                    25 * time.Millisecond,
		AckDelayExponent:               3,
		MaxIdleTimeout:                 30 * time.Second,
		HandshakeIdleTimeout:           10 * time.Second,
		MaxUDPPayloadSize:              1452,
		PMTUInitial:                    1252,
		PMTUSearchStep:                 24,
		PMTUSearchInterval:             30 * time.Second,
		PMTUMaxProbes:                  5,
		ActiveConnectionIDLimit:        8,
		InitialMaxData:                 15 << 20,
		InitialMaxStreamDataBidiLocal:  6 << 20,
		InitialMaxStreamDataBidiRemote: 6 << 20,
		InitialMaxStreamDataUni:        6 << 20,
		InitialMaxStreamsBidi:          100,
		InitialMaxStreamsUni:           100,
		MaxStreamReceiveWindow:         16 << 20,
		MaxConnectionReceiveWindow:     24 << 20,
		CIDRotateInterval:              5 * time.Minute,
	}
}

// IsZero reports whether c is the zero value (no fields set). Used by
// callers that want to substitute Default() for an unconfigured
// ChromeH3.
func (c ChromeH3) IsZero() bool {
	return c == ChromeH3{}
}

// ApplyToQUICConfig fills in the server-side quic-go configuration
// from cfg so that the values quic-go puts on the wire match Chrome
// HTTP/3. Fields the caller has already set to a non-zero value are
// preserved so that explicit overrides win.
func ApplyToQUICConfig(qc *quic.Config, cfg ChromeH3) {
	if qc == nil {
		return
	}
	if qc.HandshakeIdleTimeout == 0 {
		qc.HandshakeIdleTimeout = cfg.HandshakeIdleTimeout
	}
	if qc.MaxIdleTimeout == 0 {
		qc.MaxIdleTimeout = cfg.MaxIdleTimeout
	}
	if qc.InitialStreamReceiveWindow == 0 {
		qc.InitialStreamReceiveWindow = cfg.InitialMaxStreamDataBidiRemote
	}
	if qc.MaxStreamReceiveWindow == 0 {
		qc.MaxStreamReceiveWindow = cfg.MaxStreamReceiveWindow
	}
	if qc.InitialConnectionReceiveWindow == 0 {
		qc.InitialConnectionReceiveWindow = cfg.InitialMaxData
	}
	if qc.MaxConnectionReceiveWindow == 0 {
		qc.MaxConnectionReceiveWindow = cfg.MaxConnectionReceiveWindow
	}
	if qc.MaxIncomingStreams == 0 {
		qc.MaxIncomingStreams = int64(cfg.InitialMaxStreamsBidi)
	}
	if qc.MaxIncomingUniStreams == 0 {
		qc.MaxIncomingUniStreams = int64(cfg.InitialMaxStreamsUni)
	}
	if qc.InitialPacketSize == 0 {
		qc.InitialPacketSize = cfg.PMTUInitial
	}
	// Chrome does not rely on QUIC keep-alive; the application layer
	// emits PINGs. Leave qc.KeepAlivePeriod untouched.
}
