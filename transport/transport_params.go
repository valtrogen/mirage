package transport

import (
	"errors"
	"fmt"
)

// QUIC transport parameter IDs per RFC 9000 §18.2.
const (
	TPOriginalDestinationCID         uint64 = 0x00
	TPMaxIdleTimeout                 uint64 = 0x01
	TPStatelessResetToken            uint64 = 0x02
	TPMaxUDPPayloadSize              uint64 = 0x03
	TPInitialMaxData                 uint64 = 0x04
	TPInitialMaxStreamDataBidiLocal  uint64 = 0x05
	TPInitialMaxStreamDataBidiRemote uint64 = 0x06
	TPInitialMaxStreamDataUni        uint64 = 0x07
	TPInitialMaxStreamsBidi          uint64 = 0x08
	TPInitialMaxStreamsUni           uint64 = 0x09
	TPAckDelayExponent               uint64 = 0x0A
	TPMaxAckDelay                    uint64 = 0x0B
	TPDisableActiveMigration         uint64 = 0x0C
	TPPreferredAddress               uint64 = 0x0D
	TPActiveConnectionIDLimit        uint64 = 0x0E
	TPInitialSourceConnectionID      uint64 = 0x0F
	TPRetrySourceConnectionID        uint64 = 0x10
)

// TransportParameters is the subset of QUIC transport parameters mirage
// emits and parses. Unknown parameters are preserved on read but mirage
// does not act on them.
type TransportParameters struct {
	OriginalDestinationCID         []byte
	InitialSourceConnectionID      []byte
	RetrySourceConnectionID        []byte
	MaxIdleTimeoutMillis           uint64
	MaxUDPPayloadSize              uint64
	InitialMaxData                 uint64
	InitialMaxStreamDataBidiLocal  uint64
	InitialMaxStreamDataBidiRemote uint64
	InitialMaxStreamDataUni        uint64
	InitialMaxStreamsBidi          uint64
	InitialMaxStreamsUni           uint64
	AckDelayExponent               uint64
	MaxAckDelayMillis              uint64
	DisableActiveMigration         bool
	ActiveConnectionIDLimit        uint64
}

// Marshal encodes tp to the wire format defined in RFC 9000 §18.
func (tp *TransportParameters) Marshal() []byte {
	var b []byte
	appendInt := func(id, v uint64) {
		b = AppendVarInt(b, id)
		b = AppendVarInt(b, uint64(VarIntLen(v)))
		b = AppendVarInt(b, v)
	}
	appendBytes := func(id uint64, v []byte) {
		if len(v) == 0 {
			return
		}
		b = AppendVarInt(b, id)
		b = AppendVarInt(b, uint64(len(v)))
		b = append(b, v...)
	}
	appendFlag := func(id uint64) {
		b = AppendVarInt(b, id)
		b = AppendVarInt(b, 0)
	}

	if tp.MaxIdleTimeoutMillis > 0 {
		appendInt(TPMaxIdleTimeout, tp.MaxIdleTimeoutMillis)
	}
	if tp.MaxUDPPayloadSize > 0 {
		appendInt(TPMaxUDPPayloadSize, tp.MaxUDPPayloadSize)
	}
	if tp.InitialMaxData > 0 {
		appendInt(TPInitialMaxData, tp.InitialMaxData)
	}
	if tp.InitialMaxStreamDataBidiLocal > 0 {
		appendInt(TPInitialMaxStreamDataBidiLocal, tp.InitialMaxStreamDataBidiLocal)
	}
	if tp.InitialMaxStreamDataBidiRemote > 0 {
		appendInt(TPInitialMaxStreamDataBidiRemote, tp.InitialMaxStreamDataBidiRemote)
	}
	if tp.InitialMaxStreamDataUni > 0 {
		appendInt(TPInitialMaxStreamDataUni, tp.InitialMaxStreamDataUni)
	}
	if tp.InitialMaxStreamsBidi > 0 {
		appendInt(TPInitialMaxStreamsBidi, tp.InitialMaxStreamsBidi)
	}
	if tp.InitialMaxStreamsUni > 0 {
		appendInt(TPInitialMaxStreamsUni, tp.InitialMaxStreamsUni)
	}
	if tp.AckDelayExponent > 0 {
		appendInt(TPAckDelayExponent, tp.AckDelayExponent)
	}
	if tp.MaxAckDelayMillis > 0 {
		appendInt(TPMaxAckDelay, tp.MaxAckDelayMillis)
	}
	if tp.ActiveConnectionIDLimit > 0 {
		appendInt(TPActiveConnectionIDLimit, tp.ActiveConnectionIDLimit)
	}
	if tp.DisableActiveMigration {
		appendFlag(TPDisableActiveMigration)
	}
	appendBytes(TPOriginalDestinationCID, tp.OriginalDestinationCID)
	appendBytes(TPInitialSourceConnectionID, tp.InitialSourceConnectionID)
	appendBytes(TPRetrySourceConnectionID, tp.RetrySourceConnectionID)
	return b
}

// ParseTransportParameters decodes a transport parameter sequence.
// Unknown parameter IDs are skipped.
func ParseTransportParameters(b []byte) (*TransportParameters, error) {
	tp := &TransportParameters{}
	for len(b) > 0 {
		id, n, err := ReadVarInt(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		ln, n, err := ReadVarInt(b)
		if err != nil {
			return nil, err
		}
		b = b[n:]
		if uint64(len(b)) < ln {
			return nil, fmt.Errorf("mirage: transport parameter 0x%x truncated", id)
		}
		val := b[:ln]
		b = b[ln:]

		switch id {
		case TPOriginalDestinationCID:
			tp.OriginalDestinationCID = append([]byte(nil), val...)
		case TPInitialSourceConnectionID:
			tp.InitialSourceConnectionID = append([]byte(nil), val...)
		case TPRetrySourceConnectionID:
			tp.RetrySourceConnectionID = append([]byte(nil), val...)
		case TPMaxIdleTimeout,
			TPMaxUDPPayloadSize,
			TPInitialMaxData,
			TPInitialMaxStreamDataBidiLocal,
			TPInitialMaxStreamDataBidiRemote,
			TPInitialMaxStreamDataUni,
			TPInitialMaxStreamsBidi,
			TPInitialMaxStreamsUni,
			TPAckDelayExponent,
			TPMaxAckDelay,
			TPActiveConnectionIDLimit:
			v, _, err := ReadVarInt(val)
			if err != nil {
				return nil, err
			}
			switch id {
			case TPMaxIdleTimeout:
				tp.MaxIdleTimeoutMillis = v
			case TPMaxUDPPayloadSize:
				tp.MaxUDPPayloadSize = v
			case TPInitialMaxData:
				tp.InitialMaxData = v
			case TPInitialMaxStreamDataBidiLocal:
				tp.InitialMaxStreamDataBidiLocal = v
			case TPInitialMaxStreamDataBidiRemote:
				tp.InitialMaxStreamDataBidiRemote = v
			case TPInitialMaxStreamDataUni:
				tp.InitialMaxStreamDataUni = v
			case TPInitialMaxStreamsBidi:
				tp.InitialMaxStreamsBidi = v
			case TPInitialMaxStreamsUni:
				tp.InitialMaxStreamsUni = v
			case TPAckDelayExponent:
				tp.AckDelayExponent = v
			case TPMaxAckDelay:
				tp.MaxAckDelayMillis = v
			case TPActiveConnectionIDLimit:
				tp.ActiveConnectionIDLimit = v
			}
		case TPDisableActiveMigration:
			if ln != 0 {
				return nil, errors.New("mirage: disable_active_migration must be empty")
			}
			tp.DisableActiveMigration = true
		}
	}
	return tp, nil
}
