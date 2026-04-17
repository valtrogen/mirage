package behavior

import (
	"time"

	"github.com/valtrogen/mirage/transport"
)

// ApplyToTransportParameters fills in the timing- and sizing-related
// fields of tp from cfg. Fields that are connection-specific
// (OriginalDestinationCID, InitialSourceConnectionID, ...) are left
// untouched so the caller can still set them.
func ApplyToTransportParameters(tp *transport.TransportParameters, cfg ChromeH3) {
	if tp == nil {
		return
	}
	tp.MaxIdleTimeoutMillis = uint64(cfg.MaxIdleTimeout / time.Millisecond)
	tp.MaxUDPPayloadSize = cfg.MaxUDPPayloadSize
	tp.AckDelayExponent = uint64(cfg.AckDelayExponent)
	tp.MaxAckDelayMillis = uint64(cfg.MaxAckDelay / time.Millisecond)
	tp.ActiveConnectionIDLimit = cfg.ActiveConnectionIDLimit
}
