package proto

// FrameType is the 1-byte type tag of a mirage control-stream frame.
//
// Control frames travel on a single bidirectional QUIC stream opened by
// the server right after handshake. Each frame is:
//
//	+--------+----------------+-----------------------+
//	|  Type  |  Length (BE16) |  Body (Length bytes)  |
//	+--------+----------------+-----------------------+
//
// Receivers must silently ignore unknown frame types.
type FrameType byte

const (
	// FrameTypeReserved is the zero value and must not appear on the wire.
	FrameTypeReserved FrameType = 0x00

	// FrameTypeConnectionRecycleHint asks the client to begin migrating
	// to a new mirage connection.
	//
	// Body:
	//   +-----------------------+
	//   |  HandoffWindowMillis  |  (BE16)
	//   +-----------------------+
	//
	// The server keeps accepting new streams for HandoffWindowMillis
	// after sending the hint, then refuses new streams; in-flight
	// streams drain until they complete or a hard timeout fires.
	FrameTypeConnectionRecycleHint FrameType = 0x01

	// FrameTypeKeepalivePadding carries opaque bytes used to fill in
	// idle gaps. Bodies must be discarded by the receiver.
	FrameTypeKeepalivePadding FrameType = 0x02
)

// FrameHeaderLen is the size of a control-stream frame header
// (1-byte Type + 2-byte big-endian Length).
const FrameHeaderLen = 3

// MaxFrameBodyLen is the maximum permitted Body length for a control
// frame. Larger frames are a protocol violation.
const MaxFrameBodyLen = 0xFFFF

// MirageErrorProtocol is the QUIC application error code used to signal
// a protocol violation by the peer. 0x4D49 is "MI" in ASCII.
const MirageErrorProtocol uint64 = 0x4D49
