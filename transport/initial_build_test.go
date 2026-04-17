package transport

import (
	"bytes"
	"testing"
)

func TestBuildAndParseInitialRoundTrip(t *testing.T) {
	dcid := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	scid := []byte{9, 10, 11}
	sid := bytes.Repeat([]byte{0xAA}, 32)
	hs := BuildClientHelloHandshake(sid)
	cf := BuildCRYPTOFrame(hs)
	pkt, err := BuildInitial(dcid, scid, 7, cf, 1200)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if len(pkt) != 1200 {
		t.Fatalf("len=%d", len(pkt))
	}

	got, err := ParseInitial(pkt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !bytes.Equal(got.DCID, dcid) {
		t.Fatalf("dcid: %x", got.DCID)
	}
	if !bytes.Equal(got.SCID, scid) {
		t.Fatalf("scid: %x", got.SCID)
	}
	if got.PacketNumber != 7 {
		t.Fatalf("pn=%d", got.PacketNumber)
	}

	rebuilt, err := ExtractCRYPTOData(got.Payload)
	if err != nil {
		t.Fatalf("ExtractCRYPTO: %v", err)
	}
	gotSID, err := ExtractClientHelloSessionID(rebuilt)
	if err != nil {
		t.Fatalf("ExtractCH: %v", err)
	}
	if !bytes.Equal(gotSID, sid) {
		t.Fatalf("session_id: %x", gotSID)
	}
}
