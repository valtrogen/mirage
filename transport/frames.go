package transport

import (
	"errors"
	"fmt"
)

// QUIC frame type identifiers per RFC 9000 §19. Only the frames mirage
// emits or consumes during a minimal client handshake and stream
// exchange are listed here; unknown types are surfaced via
// ErrUnknownFrameType during parsing.
const (
	FrameTypePadding            uint64 = 0x00
	FrameTypePing               uint64 = 0x01
	FrameTypeAck                uint64 = 0x02
	FrameTypeAckECN             uint64 = 0x03
	FrameTypeResetStream        uint64 = 0x04
	FrameTypeStopSending        uint64 = 0x05
	FrameTypeCrypto             uint64 = 0x06
	FrameTypeNewToken           uint64 = 0x07
	FrameTypeStreamBase         uint64 = 0x08
	FrameTypeStreamMax          uint64 = 0x0F
	FrameTypeMaxData            uint64 = 0x10
	FrameTypeMaxStreamData      uint64 = 0x11
	FrameTypeMaxStreamsBidi     uint64 = 0x12
	FrameTypeMaxStreamsUni      uint64 = 0x13
	FrameTypeDataBlocked        uint64 = 0x14
	FrameTypeStreamDataBlocked  uint64 = 0x15
	FrameTypeStreamsBlockedBidi uint64 = 0x16
	FrameTypeStreamsBlockedUni  uint64 = 0x17
	FrameTypeNewConnectionID    uint64 = 0x18
	FrameTypeRetireConnectionID uint64 = 0x19
	FrameTypePathChallenge      uint64 = 0x1A
	FrameTypePathResponse       uint64 = 0x1B
	FrameTypeConnectionCloseT   uint64 = 0x1C
	FrameTypeConnectionCloseA   uint64 = 0x1D
	FrameTypeHandshakeDone      uint64 = 0x1E
)

// ErrFrameTruncated is returned when a frame's body is shorter than its
// header indicates.
var ErrFrameTruncated = errors.New("mirage: frame truncated")

// ErrUnknownFrameType is returned when a frame type is encountered that
// the parser does not recognise.
var ErrUnknownFrameType = errors.New("mirage: unknown frame type")

// Frame is the common interface for parsed QUIC frames.
type Frame interface {
	frameType() uint64
}

// CryptoFrame carries TLS handshake bytes within an encryption level.
type CryptoFrame struct {
	Offset uint64
	Data   []byte
}

func (CryptoFrame) frameType() uint64 { return FrameTypeCrypto }

// AckRange is one contiguous gap-then-range pair in an ACK frame. The
// gap and ack length are RFC 9000 §19.3 encoded values; absolute packet
// numbers are reconstructed by AckFrame.PacketNumbers.
type AckRange struct {
	Gap    uint64
	AckLen uint64
}

// AckFrame represents a parsed ACK frame (no ECN counts).
type AckFrame struct {
	LargestAcked uint64
	AckDelay     uint64
	FirstAckLen  uint64
	Ranges       []AckRange
}

func (AckFrame) frameType() uint64 { return FrameTypeAck }

// StreamFrame carries application data on a single QUIC stream.
type StreamFrame struct {
	StreamID uint64
	Offset   uint64
	Data     []byte
	Fin      bool
}

func (StreamFrame) frameType() uint64 { return FrameTypeStreamBase }

// PingFrame is the single-byte 0x01 PING frame.
type PingFrame struct{}

func (PingFrame) frameType() uint64 { return FrameTypePing }

// PaddingFrame represents one or more contiguous 0x00 bytes coalesced
// into a single record. Length is the number of padding bytes.
type PaddingFrame struct {
	Length int
}

func (PaddingFrame) frameType() uint64 { return FrameTypePadding }

// HandshakeDoneFrame is the single-byte 0x1E frame the server sends to
// signal the end of the handshake.
type HandshakeDoneFrame struct{}

func (HandshakeDoneFrame) frameType() uint64 { return FrameTypeHandshakeDone }

// ConnectionCloseFrame represents a CONNECTION_CLOSE (transport or
// application). IsApp distinguishes 0x1C (transport) from 0x1D
// (application); FrameType is set only for transport closes.
type ConnectionCloseFrame struct {
	IsApp     bool
	ErrorCode uint64
	FrameType uint64
	Reason    []byte
}

func (ConnectionCloseFrame) frameType() uint64 { return FrameTypeConnectionCloseT }

// NewConnectionIDFrame is parsed but mirage does not act on it during
// the minimal client flow; the connection keeps using the original
// server-chosen DCID.
type NewConnectionIDFrame struct {
	SequenceNumber uint64
	RetirePriorTo  uint64
	ConnectionID   []byte
	StatelessReset [16]byte
}

func (NewConnectionIDFrame) frameType() uint64 { return FrameTypeNewConnectionID }

// NewTokenFrame is parsed (and discarded) when the server offers an
// address validation token via 0x07.
type NewTokenFrame struct {
	Token []byte
}

func (NewTokenFrame) frameType() uint64 { return FrameTypeNewToken }

// MaxDataFrame raises the connection-level send credit (RFC 9000
// §19.9). Maximum is the absolute byte offset across all streams the
// receiver authorises the sender to deliver.
type MaxDataFrame struct {
	Maximum uint64
}

func (MaxDataFrame) frameType() uint64 { return FrameTypeMaxData }

// MaxStreamDataFrame raises a single stream's send credit (RFC 9000
// §19.10). Maximum is the absolute byte offset on StreamID the
// receiver authorises the sender to deliver.
type MaxStreamDataFrame struct {
	StreamID uint64
	Maximum  uint64
}

func (MaxStreamDataFrame) frameType() uint64 { return FrameTypeMaxStreamData }

// ResetStreamFrame is the RESET_STREAM frame (RFC 9000 §19.4): the
// sender abruptly terminates the sending part of a stream. ErrorCode
// is application-defined; FinalSize is the absolute byte offset the
// peer has now committed to.
type ResetStreamFrame struct {
	StreamID  uint64
	ErrorCode uint64
	FinalSize uint64
}

func (ResetStreamFrame) frameType() uint64 { return FrameTypeResetStream }

// StopSendingFrame is the STOP_SENDING frame (RFC 9000 §19.5): the
// receiver asks the peer to stop sending on a stream. The peer is
// expected to respond with RESET_STREAM. ErrorCode is application-
// defined.
type StopSendingFrame struct {
	StreamID  uint64
	ErrorCode uint64
}

func (StopSendingFrame) frameType() uint64 { return FrameTypeStopSending }

// ParseFrames walks payload, returning every frame in order. Padding
// runs are coalesced into a single PaddingFrame for convenience. The
// caller is responsible for enforcing per-encryption-level frame
// admissibility (RFC 9000 §12.4).
func ParseFrames(payload []byte) ([]Frame, error) {
	var frames []Frame
	for len(payload) > 0 {
		t, n, err := ReadVarInt(payload)
		if err != nil {
			return nil, err
		}
		payload = payload[n:]

		switch {
		case t == FrameTypePadding:
			pad := 1
			for len(payload) > 0 && payload[0] == 0x00 {
				pad++
				payload = payload[1:]
			}
			frames = append(frames, PaddingFrame{Length: pad})
		case t == FrameTypePing:
			frames = append(frames, PingFrame{})
		case t == FrameTypeAck || t == FrameTypeAckECN:
			f, rest, err := parseAck(payload, t == FrameTypeAckECN)
			if err != nil {
				return nil, err
			}
			frames = append(frames, f)
			payload = rest
		case t == FrameTypeCrypto:
			off, n1, err := ReadVarInt(payload)
			if err != nil {
				return nil, err
			}
			ln, n2, err := ReadVarInt(payload[n1:])
			if err != nil {
				return nil, err
			}
			start := n1 + n2
			if uint64(len(payload)-start) < ln {
				return nil, ErrFrameTruncated
			}
			data := payload[start : start+int(ln)]
			frames = append(frames, CryptoFrame{Offset: off, Data: data})
			payload = payload[start+int(ln):]
		case t == FrameTypeNewToken:
			ln, nl, err := ReadVarInt(payload)
			if err != nil {
				return nil, err
			}
			if uint64(len(payload)-nl) < ln {
				return nil, ErrFrameTruncated
			}
			frames = append(frames, NewTokenFrame{Token: payload[nl : nl+int(ln)]})
			payload = payload[nl+int(ln):]
		case t >= FrameTypeStreamBase && t <= FrameTypeStreamMax:
			f, rest, err := parseStream(payload, t)
			if err != nil {
				return nil, err
			}
			frames = append(frames, f)
			payload = rest
		case t == FrameTypeNewConnectionID:
			f, rest, err := parseNewConnectionID(payload)
			if err != nil {
				return nil, err
			}
			frames = append(frames, f)
			payload = rest
		case t == FrameTypeConnectionCloseT, t == FrameTypeConnectionCloseA:
			f, rest, err := parseConnectionClose(payload, t == FrameTypeConnectionCloseA)
			if err != nil {
				return nil, err
			}
			frames = append(frames, f)
			payload = rest
		case t == FrameTypeHandshakeDone:
			frames = append(frames, HandshakeDoneFrame{})
		case t == FrameTypeMaxData:
			max, n, err := ReadVarInt(payload)
			if err != nil {
				return nil, err
			}
			frames = append(frames, MaxDataFrame{Maximum: max})
			payload = payload[n:]
		case t == FrameTypeMaxStreamsBidi,
			t == FrameTypeMaxStreamsUni,
			t == FrameTypeDataBlocked,
			t == FrameTypeStreamsBlockedBidi,
			t == FrameTypeStreamsBlockedUni,
			t == FrameTypeRetireConnectionID:
			_, n, err := ReadVarInt(payload)
			if err != nil {
				return nil, err
			}
			payload = payload[n:]
		case t == FrameTypeMaxStreamData:
			id, n1, err := ReadVarInt(payload)
			if err != nil {
				return nil, err
			}
			max, n2, err := ReadVarInt(payload[n1:])
			if err != nil {
				return nil, err
			}
			frames = append(frames, MaxStreamDataFrame{StreamID: id, Maximum: max})
			payload = payload[n1+n2:]
		case t == FrameTypeStreamDataBlocked:
			_, n1, err := ReadVarInt(payload)
			if err != nil {
				return nil, err
			}
			_, n2, err := ReadVarInt(payload[n1:])
			if err != nil {
				return nil, err
			}
			payload = payload[n1+n2:]
		case t == FrameTypeResetStream:
			id, n1, err := ReadVarInt(payload)
			if err != nil {
				return nil, err
			}
			ec, n2, err := ReadVarInt(payload[n1:])
			if err != nil {
				return nil, err
			}
			fs, n3, err := ReadVarInt(payload[n1+n2:])
			if err != nil {
				return nil, err
			}
			frames = append(frames, ResetStreamFrame{StreamID: id, ErrorCode: ec, FinalSize: fs})
			payload = payload[n1+n2+n3:]
		case t == FrameTypeStopSending:
			id, n1, err := ReadVarInt(payload)
			if err != nil {
				return nil, err
			}
			ec, n2, err := ReadVarInt(payload[n1:])
			if err != nil {
				return nil, err
			}
			frames = append(frames, StopSendingFrame{StreamID: id, ErrorCode: ec})
			payload = payload[n1+n2:]
		case t == FrameTypePathChallenge, t == FrameTypePathResponse:
			if len(payload) < 8 {
				return nil, ErrFrameTruncated
			}
			payload = payload[8:]
		default:
			return nil, fmt.Errorf("%w: 0x%x", ErrUnknownFrameType, t)
		}
	}
	return frames, nil
}

func parseAck(payload []byte, ecn bool) (AckFrame, []byte, error) {
	largest, n1, err := ReadVarInt(payload)
	if err != nil {
		return AckFrame{}, nil, err
	}
	delay, n2, err := ReadVarInt(payload[n1:])
	if err != nil {
		return AckFrame{}, nil, err
	}
	rangeCount, n3, err := ReadVarInt(payload[n1+n2:])
	if err != nil {
		return AckFrame{}, nil, err
	}
	first, n4, err := ReadVarInt(payload[n1+n2+n3:])
	if err != nil {
		return AckFrame{}, nil, err
	}
	off := n1 + n2 + n3 + n4
	// Sanity bound: a varint can encode up to 2^62 - 1, far more than
	// any legitimate ACK frame contains. Cap the preallocation at the
	// number of varint pairs the remaining payload could possibly
	// hold (one byte minimum per varint, so two bytes per range).
	// Without this cap a hostile peer can crash the parser via a
	// ranges-count of 2^62 making make() panic with "cap out of
	// range".
	maxPossible := uint64(len(payload)-off) / 2
	if rangeCount > maxPossible {
		return AckFrame{}, nil, ErrFrameTruncated
	}
	ranges := make([]AckRange, 0, rangeCount)
	for i := uint64(0); i < rangeCount; i++ {
		gap, gn, err := ReadVarInt(payload[off:])
		if err != nil {
			return AckFrame{}, nil, err
		}
		al, an, err := ReadVarInt(payload[off+gn:])
		if err != nil {
			return AckFrame{}, nil, err
		}
		ranges = append(ranges, AckRange{Gap: gap, AckLen: al})
		off += gn + an
	}
	if ecn {
		for i := 0; i < 3; i++ {
			_, n, err := ReadVarInt(payload[off:])
			if err != nil {
				return AckFrame{}, nil, err
			}
			off += n
		}
	}
	return AckFrame{
		LargestAcked: largest,
		AckDelay:     delay,
		FirstAckLen:  first,
		Ranges:       ranges,
	}, payload[off:], nil
}

func parseStream(payload []byte, t uint64) (StreamFrame, []byte, error) {
	hasOffset := t&0x04 != 0
	hasLength := t&0x02 != 0
	fin := t&0x01 != 0

	id, n1, err := ReadVarInt(payload)
	if err != nil {
		return StreamFrame{}, nil, err
	}
	off := n1
	var streamOffset uint64
	if hasOffset {
		v, n, err := ReadVarInt(payload[off:])
		if err != nil {
			return StreamFrame{}, nil, err
		}
		streamOffset = v
		off += n
	}
	var data []byte
	if hasLength {
		ln, n, err := ReadVarInt(payload[off:])
		if err != nil {
			return StreamFrame{}, nil, err
		}
		off += n
		if uint64(len(payload)-off) < ln {
			return StreamFrame{}, nil, ErrFrameTruncated
		}
		data = payload[off : off+int(ln)]
		off += int(ln)
	} else {
		data = payload[off:]
		off = len(payload)
	}
	return StreamFrame{
		StreamID: id,
		Offset:   streamOffset,
		Data:     data,
		Fin:      fin,
	}, payload[off:], nil
}

func parseNewConnectionID(payload []byte) (NewConnectionIDFrame, []byte, error) {
	seq, n1, err := ReadVarInt(payload)
	if err != nil {
		return NewConnectionIDFrame{}, nil, err
	}
	retire, n2, err := ReadVarInt(payload[n1:])
	if err != nil {
		return NewConnectionIDFrame{}, nil, err
	}
	off := n1 + n2
	if off >= len(payload) {
		return NewConnectionIDFrame{}, nil, ErrFrameTruncated
	}
	cidLen := int(payload[off])
	off++
	if len(payload)-off < cidLen+16 {
		return NewConnectionIDFrame{}, nil, ErrFrameTruncated
	}
	cid := payload[off : off+cidLen]
	off += cidLen
	var srt [16]byte
	copy(srt[:], payload[off:off+16])
	off += 16
	return NewConnectionIDFrame{
		SequenceNumber: seq,
		RetirePriorTo:  retire,
		ConnectionID:   append([]byte(nil), cid...),
		StatelessReset: srt,
	}, payload[off:], nil
}

func parseConnectionClose(payload []byte, isApp bool) (ConnectionCloseFrame, []byte, error) {
	code, n1, err := ReadVarInt(payload)
	if err != nil {
		return ConnectionCloseFrame{}, nil, err
	}
	off := n1
	var ftype uint64
	if !isApp {
		v, n, err := ReadVarInt(payload[off:])
		if err != nil {
			return ConnectionCloseFrame{}, nil, err
		}
		ftype = v
		off += n
	}
	rl, n2, err := ReadVarInt(payload[off:])
	if err != nil {
		return ConnectionCloseFrame{}, nil, err
	}
	off += n2
	if uint64(len(payload)-off) < rl {
		return ConnectionCloseFrame{}, nil, ErrFrameTruncated
	}
	reason := payload[off : off+int(rl)]
	off += int(rl)
	return ConnectionCloseFrame{
		IsApp:     isApp,
		ErrorCode: code,
		FrameType: ftype,
		Reason:    append([]byte(nil), reason...),
	}, payload[off:], nil
}

// AppendCryptoFrame appends a CRYPTO frame carrying data at the given
// offset to b and returns the extended slice.
func AppendCryptoFrame(b []byte, offset uint64, data []byte) []byte {
	b = AppendVarInt(b, FrameTypeCrypto)
	b = AppendVarInt(b, offset)
	b = AppendVarInt(b, uint64(len(data)))
	b = append(b, data...)
	return b
}

// AppendAckFrame appends an ACK frame for a single contiguous range
// [largest-firstLen, largest]. Higher-level callers can synthesise more
// elaborate ACKs via AppendAckFrameRanges.
func AppendAckFrame(b []byte, largest, ackDelay, firstAckLen uint64) []byte {
	b = AppendVarInt(b, FrameTypeAck)
	b = AppendVarInt(b, largest)
	b = AppendVarInt(b, ackDelay)
	b = AppendVarInt(b, 0)
	b = AppendVarInt(b, firstAckLen)
	return b
}

// AppendAckFrameRanges builds an ACK frame for a sorted, descending
// list of received packet numbers (largest first, no duplicates). It
// emits the contiguous run anchored at the largest as first_ack_range
// then encodes any earlier runs as gap/range pairs per RFC 9000 §19.3.
func AppendAckFrameRanges(b []byte, ackDelay uint64, descending []uint64) []byte {
	if len(descending) == 0 {
		return b
	}
	type run struct{ hi, lo uint64 }
	runs := make([]run, 0, 4)
	cur := run{hi: descending[0], lo: descending[0]}
	for _, n := range descending[1:] {
		if n+1 == cur.lo {
			cur.lo = n
			continue
		}
		runs = append(runs, cur)
		cur = run{hi: n, lo: n}
	}
	runs = append(runs, cur)

	first := runs[0]
	rest := runs[1:]
	b = AppendVarInt(b, FrameTypeAck)
	b = AppendVarInt(b, first.hi)
	b = AppendVarInt(b, ackDelay)
	b = AppendVarInt(b, uint64(len(rest)))
	b = AppendVarInt(b, first.hi-first.lo)

	prevLo := first.lo
	for _, r := range rest {
		gap := prevLo - r.hi - 2
		ackLen := r.hi - r.lo
		b = AppendVarInt(b, gap)
		b = AppendVarInt(b, ackLen)
		prevLo = r.lo
	}
	return b
}

// AppendAckFrameFromBitmap appends an ACK frame derived from a
// sliding-window bitmap. last is the highest packet number known
// received; bitmap bit i is set when (last - i) was received. The
// helper short-circuits to AppendAckFrameRanges, exercising the same
// gap/range encoder so the wire result is identical to the explicit
// path used by tests.
//
// AppendAckFrameFromBitmap is intended for receivers that track ACK
// state with a single 64-bit window instead of a per-PN map; it
// performs no allocation beyond the appended bytes.
func AppendAckFrameFromBitmap(b []byte, ackDelay uint64, last uint64, bitmap uint64) []byte {
	if bitmap == 0 {
		return b
	}
	pns := make([]uint64, 0, 64)
	for i := uint64(0); i < 64; i++ {
		if bitmap&(uint64(1)<<i) == 0 {
			continue
		}
		if i > last {
			break
		}
		pns = append(pns, last-i)
	}
	return AppendAckFrameRanges(b, ackDelay, pns)
}

// AppendStreamFrame appends a STREAM frame. The OFF and LEN bits are
// always set so the frame can sit anywhere in a packet payload; FIN is
// set when fin is true.
func AppendStreamFrame(b []byte, streamID, offset uint64, data []byte, fin bool) []byte {
	t := FrameTypeStreamBase | 0x04 | 0x02
	if fin {
		t |= 0x01
	}
	b = AppendVarInt(b, t)
	b = AppendVarInt(b, streamID)
	b = AppendVarInt(b, offset)
	b = AppendVarInt(b, uint64(len(data)))
	b = append(b, data...)
	return b
}

// AppendPingFrame appends a single PING frame.
func AppendPingFrame(b []byte) []byte {
	return append(b, byte(FrameTypePing))
}

// AppendPaddingFrames appends n PADDING frames.
func AppendPaddingFrames(b []byte, n int) []byte {
	for i := 0; i < n; i++ {
		b = append(b, 0x00)
	}
	return b
}

// AppendMaxDataFrame appends a MAX_DATA frame (RFC 9000 §19.9) raising
// the receiver's connection-level send credit to maximum.
func AppendMaxDataFrame(b []byte, maximum uint64) []byte {
	b = AppendVarInt(b, FrameTypeMaxData)
	b = AppendVarInt(b, maximum)
	return b
}

// AppendMaxStreamDataFrame appends a MAX_STREAM_DATA frame (RFC 9000
// §19.10) raising streamID's send credit to maximum.
func AppendMaxStreamDataFrame(b []byte, streamID, maximum uint64) []byte {
	b = AppendVarInt(b, FrameTypeMaxStreamData)
	b = AppendVarInt(b, streamID)
	b = AppendVarInt(b, maximum)
	return b
}

// AppendDataBlockedFrame appends a DATA_BLOCKED frame (RFC 9000
// §19.12) reporting that the sender has data to send but is blocked by
// the connection-level flow control limit.
func AppendDataBlockedFrame(b []byte, limit uint64) []byte {
	b = AppendVarInt(b, FrameTypeDataBlocked)
	b = AppendVarInt(b, limit)
	return b
}

// AppendStreamDataBlockedFrame appends a STREAM_DATA_BLOCKED frame
// (RFC 9000 §19.13) reporting that streamID is blocked by the
// stream-level flow control limit.
func AppendStreamDataBlockedFrame(b []byte, streamID, limit uint64) []byte {
	b = AppendVarInt(b, FrameTypeStreamDataBlocked)
	b = AppendVarInt(b, streamID)
	b = AppendVarInt(b, limit)
	return b
}

// AppendResetStreamFrame appends a RESET_STREAM frame (RFC 9000 §19.4).
// errorCode is application-defined; finalSize is the absolute stream
// offset at which the sender stops emitting bytes.
func AppendResetStreamFrame(b []byte, streamID, errorCode, finalSize uint64) []byte {
	b = AppendVarInt(b, FrameTypeResetStream)
	b = AppendVarInt(b, streamID)
	b = AppendVarInt(b, errorCode)
	b = AppendVarInt(b, finalSize)
	return b
}

// AppendRetireConnectionIDFrame appends a RETIRE_CONNECTION_ID frame
// (RFC 9000 §19.16). The receiver is expected to stop using the
// connection ID with the given sequence number and remove it from
// its issued set.
func AppendRetireConnectionIDFrame(b []byte, sequenceNumber uint64) []byte {
	b = AppendVarInt(b, FrameTypeRetireConnectionID)
	b = AppendVarInt(b, sequenceNumber)
	return b
}

// AppendStopSendingFrame appends a STOP_SENDING frame (RFC 9000 §19.5).
// errorCode is application-defined and indicates why the receiver no
// longer wants to read.
func AppendStopSendingFrame(b []byte, streamID, errorCode uint64) []byte {
	b = AppendVarInt(b, FrameTypeStopSending)
	b = AppendVarInt(b, streamID)
	b = AppendVarInt(b, errorCode)
	return b
}

// AppendConnectionCloseFrame appends a transport-level CONNECTION_CLOSE
// frame (0x1C).
func AppendConnectionCloseFrame(b []byte, errorCode, frameType uint64, reason string) []byte {
	b = AppendVarInt(b, FrameTypeConnectionCloseT)
	b = AppendVarInt(b, errorCode)
	b = AppendVarInt(b, frameType)
	b = AppendVarInt(b, uint64(len(reason)))
	b = append(b, reason...)
	return b
}
