package transport

import (
	"bytes"
	"testing"
)

func TestTransportParametersRoundTrip(t *testing.T) {
	tp := &TransportParameters{
		MaxIdleTimeoutMillis:           30000,
		MaxUDPPayloadSize:              1452,
		InitialMaxData:                 1 << 22,
		InitialMaxStreamDataBidiLocal:  1 << 20,
		InitialMaxStreamDataBidiRemote: 1 << 20,
		InitialMaxStreamDataUni:        1 << 20,
		InitialMaxStreamsBidi:          100,
		InitialMaxStreamsUni:           3,
		AckDelayExponent:               3,
		MaxAckDelayMillis:              25,
		ActiveConnectionIDLimit:        4,
		DisableActiveMigration:         true,
		InitialSourceConnectionID:      []byte{0x11, 0x22, 0x33, 0x44},
	}
	enc := tp.Marshal()

	parsed, err := ParseTransportParameters(enc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.MaxIdleTimeoutMillis != tp.MaxIdleTimeoutMillis {
		t.Fatalf("idle timeout %d", parsed.MaxIdleTimeoutMillis)
	}
	if parsed.InitialMaxData != tp.InitialMaxData {
		t.Fatalf("max data %d", parsed.InitialMaxData)
	}
	if parsed.InitialMaxStreamsBidi != tp.InitialMaxStreamsBidi {
		t.Fatalf("max streams bidi %d", parsed.InitialMaxStreamsBidi)
	}
	if !parsed.DisableActiveMigration {
		t.Fatal("disable_active_migration not preserved")
	}
	if !bytes.Equal(parsed.InitialSourceConnectionID, tp.InitialSourceConnectionID) {
		t.Fatalf("initial scid %x", parsed.InitialSourceConnectionID)
	}
}

func TestTransportParametersSkipsUnknown(t *testing.T) {
	enc := []byte{}
	enc = AppendVarInt(enc, 0xBA)
	enc = AppendVarInt(enc, 4)
	enc = append(enc, 0xDE, 0xAD, 0xBE, 0xEF)
	enc = AppendVarInt(enc, TPInitialMaxData)
	enc = AppendVarInt(enc, uint64(VarIntLen(1024)))
	enc = AppendVarInt(enc, 1024)

	tp, err := ParseTransportParameters(enc)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if tp.InitialMaxData != 1024 {
		t.Fatalf("InitialMaxData %d", tp.InitialMaxData)
	}
}

func TestTransportParametersRejectsTruncated(t *testing.T) {
	enc := []byte{}
	enc = AppendVarInt(enc, TPInitialMaxData)
	enc = AppendVarInt(enc, 4)
	enc = append(enc, 0x00, 0x01)
	if _, err := ParseTransportParameters(enc); err == nil {
		t.Fatal("expected truncated error")
	}
}
