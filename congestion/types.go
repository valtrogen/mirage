package congestion

import "time"

// ByteCount counts bytes. It is an alias-friendly type used across the
// congestion API and BBRv2 internals so byte arithmetic stays explicit
// at compile time.
type ByteCount uint64

// PacketNumber identifies a 1-RTT packet. It mirrors the QUIC packet
// number space and is signed so the sentinel "invalid packet number"
// (-1) can be expressed without overflow surprises.
type PacketNumber int64

// InvalidPacketNumber is the sentinel for "no packet number assigned
// yet" / "the slot is empty".
const InvalidPacketNumber PacketNumber = -1

// AckedPacket describes one outbound packet that the peer has just
// acknowledged. Controllers receive these in batches so they can
// distinguish per-datagram acks from coalesced acks across rounds.
//
// The two timestamps are required by delivery-rate-based controllers
// (BBRv2): SentTime is when the local stack put the packet on the
// wire; ReceivedTime is when the local stack observed the ACK frame
// (not when the peer wrote it). Passing the zero time.Time means
// "unknown / use now".
type AckedPacket struct {
	PacketNumber PacketNumber
	BytesAcked   ByteCount
	SentTime     time.Time
	ReceivedTime time.Time
}

// LostPacket describes one outbound packet that the loss detector has
// declared lost. Controllers use this to react to congestion signals.
type LostPacket struct {
	PacketNumber PacketNumber
	BytesLost    ByteCount
}
