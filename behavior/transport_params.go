package behavior

import (
	"time"

	"github.com/quic-go/quic-go"

	"github.com/valtrogen/mirage/transport"
)

// ApplyToTransportParameters fills in the timing-, sizing- and flow-
// control fields of tp from cfg. Connection-specific fields
// (OriginalDestinationCID, InitialSourceConnectionID, ...) are left
// untouched so the caller can still set them.
//
// Real Chrome H3 does NOT advertise disable_active_migration; this
// helper accordingly clears tp.DisableActiveMigration.
func ApplyToTransportParameters(tp *transport.TransportParameters, cfg ChromeH3) {
	if tp == nil {
		return
	}
	tp.MaxIdleTimeoutMillis = uint64(cfg.MaxIdleTimeout / time.Millisecond)
	tp.MaxUDPPayloadSize = cfg.MaxUDPPayloadSize
	tp.AckDelayExponent = uint64(cfg.AckDelayExponent)
	tp.MaxAckDelayMillis = uint64(cfg.MaxAckDelay / time.Millisecond)
	tp.ActiveConnectionIDLimit = cfg.ActiveConnectionIDLimit
	tp.InitialMaxData = cfg.InitialMaxData
	tp.InitialMaxStreamDataBidiLocal = cfg.InitialMaxStreamDataBidiLocal
	tp.InitialMaxStreamDataBidiRemote = cfg.InitialMaxStreamDataBidiRemote
	tp.InitialMaxStreamDataUni = cfg.InitialMaxStreamDataUni
	tp.InitialMaxStreamsBidi = cfg.InitialMaxStreamsBidi
	tp.InitialMaxStreamsUni = cfg.InitialMaxStreamsUni
	tp.DisableActiveMigration = false
}

// ApplyToQUICConfig fills in the server-side quic-go configuration from
// cfg so that the values quic-go puts on the wire match Chrome H3 on the
// server side. Fields the caller has already set to a non-zero value are
// preserved so that explicit overrides win.
//
// This is the server-side counterpart to ApplyToTransportParameters.
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
	// Chrome does not rely on QUIC keep-alive (PINGs are issued by the
	// application via behavior.PingClock). Leave qc.KeepAlivePeriod at 0
	// unless the operator overrode it.
}
