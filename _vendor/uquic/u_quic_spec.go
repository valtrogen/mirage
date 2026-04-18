package quic

import tls "github.com/refraction-networking/utls"

const (
	DefaultUDPDatagramMinSize = 1200
)

type QUICSpec struct {
	// InitialPacketSpec specifies the QUIC Initial Packet, which includes Initial
	// Packet Headers and Frames.
	InitialPacketSpec InitialPacketSpec

	// ClientHelloSpec specifies the TLS ClientHello to be sent in the first Initial
	// Packet. It is implemented by the uTLS library and a valid ClientHelloSpec
	// for QUIC MUST include (utls).QUICTransportParametersExtension.
	ClientHelloSpec *tls.ClientHelloSpec

	// UDPDatagramMinSize specifies the minimum size of the UDP Datagram (UDP payload).
	// If the UDP Datagram is smaller than this size, zeros will be padded to the end
	// of the UDP Datagram until this size is reached.
	UDPDatagramMinSize int

	// PostApplyPreset is invoked once on the underlying *tls.UQUICConn after
	// ApplyPreset has been called and before Start. It exists so callers can
	// post-process the freshly-built ClientHello (e.g. set legacy_session_id
	// to a value uTLS would otherwise zero in QUIC mode per RFC 9001 §8.4).
	// Returning a non-nil error aborts the handshake.
	PostApplyPreset func(uqc *tls.UQUICConn) error
}

func (s *QUICSpec) UpdateConfig(config *Config) {
	s.InitialPacketSpec.UpdateConfig(config)
}
