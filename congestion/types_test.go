package congestion

import "testing"

func TestInvalidPacketNumberSentinel(t *testing.T) {
	if InvalidPacketNumber != -1 {
		t.Fatalf("InvalidPacketNumber = %d, want -1", InvalidPacketNumber)
	}
	if PacketNumber(0) == InvalidPacketNumber {
		t.Fatal("packet number 0 must be a valid packet number")
	}
}

func TestAckedAndLostPacketAreValueTypes(t *testing.T) {
	a := AckedPacket{PacketNumber: 7, BytesAcked: 1200}
	b := a
	b.BytesAcked = 99
	if a.BytesAcked != 1200 {
		t.Fatalf("AckedPacket should be a value type; got %d", a.BytesAcked)
	}

	l := LostPacket{PacketNumber: 9, BytesLost: 1200}
	m := l
	m.BytesLost = 0
	if l.BytesLost != 1200 {
		t.Fatalf("LostPacket should be a value type; got %d", l.BytesLost)
	}
}
