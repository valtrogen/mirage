package congestion

import "time"

// Controller is the interface a mirage client uses to throttle its
// sender. The contract is:
//
//   - The sender goroutine consults CanSend and TimeUntilSend before
//     placing the next packet on the wire.
//   - For every packet it does send, the sender calls OnPacketSent
//     before the WriteTo, passing the in-flight count *before* this
//     send.
//   - When acks or losses are observed for a coalesced batch of
//     packets (typically one inbound datagram), the receiver calls
//     OnCongestionEvent once with the full batch and the in-flight
//     count *before* the batch is applied.
//   - When the sender has nothing to send and is below cwnd, it must
//     call OnAppLimited so the controller can mark the next bandwidth
//     sample as application-limited (BBRv2 ignores those samples for
//     filtering).
//
// All time arguments are wall-clock (time.Now) rather than monotonic;
// implementations that need monotonic guarantees should snapshot time
// at construction.
type Controller interface {
	OnPacketSent(now time.Time, pn PacketNumber, bytes ByteCount,
		bytesInFlight ByteCount, retransmittable bool)

	OnCongestionEvent(now time.Time, priorBytesInFlight ByteCount,
		acked []AckedPacket, lost []LostPacket)

	OnAppLimited(bytesInFlight ByteCount)

	CanSend(bytesInFlight ByteCount) bool
	// TimeUntilSend returns how long the sender should wait before
	// putting the next packet on the wire. A return value of 0 means
	// "send immediately"; positive durations are advisory upper bounds
	// — implementations may also wake early when an ACK arrives.
	//
	// Callers MUST gate their send decision on CanSend first; this
	// method only consults the pacer's rate-based budget, not the
	// congestion window.
	TimeUntilSend(now time.Time) time.Duration

	GetCongestionWindow() ByteCount
	PacingRate() Bandwidth
	SetMaxDatagramSize(size ByteCount)
}
