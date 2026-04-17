package transport

import "errors"

// ErrVarIntTruncated is returned when a buffer is too short to hold the
// variable-length integer indicated by its first byte.
var ErrVarIntTruncated = errors.New("mirage: varint truncated")

// ReadVarInt decodes a QUIC variable-length integer from b per RFC 9000
// §16. It returns the value and the number of bytes consumed.
//
// The first two bits of b[0] select the length: 00=1, 01=2, 10=4, 11=8.
func ReadVarInt(b []byte) (value uint64, n int, err error) {
	if len(b) < 1 {
		return 0, 0, ErrVarIntTruncated
	}
	switch b[0] >> 6 {
	case 0:
		return uint64(b[0] & 0x3F), 1, nil
	case 1:
		if len(b) < 2 {
			return 0, 0, ErrVarIntTruncated
		}
		return uint64(b[0]&0x3F)<<8 | uint64(b[1]), 2, nil
	case 2:
		if len(b) < 4 {
			return 0, 0, ErrVarIntTruncated
		}
		return uint64(b[0]&0x3F)<<24 |
			uint64(b[1])<<16 |
			uint64(b[2])<<8 |
			uint64(b[3]), 4, nil
	default:
		if len(b) < 8 {
			return 0, 0, ErrVarIntTruncated
		}
		return uint64(b[0]&0x3F)<<56 |
			uint64(b[1])<<48 |
			uint64(b[2])<<40 |
			uint64(b[3])<<32 |
			uint64(b[4])<<24 |
			uint64(b[5])<<16 |
			uint64(b[6])<<8 |
			uint64(b[7]), 8, nil
	}
}

// MaxVarInt is the largest value representable by a QUIC variable-length
// integer (62 bits set).
const MaxVarInt uint64 = 0x3FFFFFFFFFFFFFFF

// AppendVarInt appends a QUIC variable-length integer encoding of v to b
// and returns the extended slice. It panics if v exceeds MaxVarInt; the
// caller is expected to validate input separately when handling
// untrusted values.
func AppendVarInt(b []byte, v uint64) []byte {
	switch {
	case v <= 0x3F:
		return append(b, byte(v))
	case v <= 0x3FFF:
		return append(b, byte(v>>8)|0x40, byte(v))
	case v <= 0x3FFFFFFF:
		return append(b,
			byte(v>>24)|0x80,
			byte(v>>16),
			byte(v>>8),
			byte(v))
	case v <= MaxVarInt:
		return append(b,
			byte(v>>56)|0xC0,
			byte(v>>48),
			byte(v>>40),
			byte(v>>32),
			byte(v>>24),
			byte(v>>16),
			byte(v>>8),
			byte(v))
	default:
		panic("mirage: varint value exceeds 62-bit limit")
	}
}

// VarIntLen returns the number of bytes needed to encode v as a QUIC
// variable-length integer. It returns 0 for values that exceed the
// 62-bit limit.
func VarIntLen(v uint64) int {
	switch {
	case v <= 0x3F:
		return 1
	case v <= 0x3FFF:
		return 2
	case v <= 0x3FFFFFFF:
		return 4
	case v <= 0x3FFFFFFFFFFFFFFF:
		return 8
	default:
		return 0
	}
}
