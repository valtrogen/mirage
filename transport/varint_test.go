package transport

import "testing"

// Vectors taken from RFC 9000 Appendix A.1.
var varIntVectors = []struct {
	enc []byte
	val uint64
}{
	{[]byte{0x25}, 37},
	{[]byte{0x40, 0x25}, 37},
	{[]byte{0x7B, 0xBD}, 15293},
	{[]byte{0x9D, 0x7F, 0x3E, 0x7D}, 494878333},
	{[]byte{0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C}, 151288809941952652},
}

func TestReadVarIntRFCVectors(t *testing.T) {
	for _, v := range varIntVectors {
		got, n, err := ReadVarInt(v.enc)
		if err != nil {
			t.Fatalf("%x: %v", v.enc, err)
		}
		if got != v.val {
			t.Fatalf("%x: got %d want %d", v.enc, got, v.val)
		}
		if n != len(v.enc) {
			t.Fatalf("%x: consumed %d want %d", v.enc, n, len(v.enc))
		}
	}
}

func TestReadVarIntTruncated(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x40},
		{0x80, 0x00},
		{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	}
	for _, c := range cases {
		if _, _, err := ReadVarInt(c); err != ErrVarIntTruncated {
			t.Fatalf("%x: want ErrVarIntTruncated got %v", c, err)
		}
	}
}

func TestAppendVarIntMinimalEncoding(t *testing.T) {
	cases := []struct {
		v    uint64
		want []byte
	}{
		{0, []byte{0x00}},
		{37, []byte{0x25}},
		{0x3F, []byte{0x3F}},
		{0x40, []byte{0x40, 0x40}},
		{15293, []byte{0x7B, 0xBD}},
		{0x3FFF, []byte{0x7F, 0xFF}},
		{0x4000, []byte{0x80, 0x00, 0x40, 0x00}},
		{494878333, []byte{0x9D, 0x7F, 0x3E, 0x7D}},
		{0x3FFFFFFF, []byte{0xBF, 0xFF, 0xFF, 0xFF}},
		{0x40000000, []byte{0xC0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00}},
		{151288809941952652, []byte{0xC2, 0x19, 0x7C, 0x5E, 0xFF, 0x14, 0xE8, 0x8C}},
	}
	for _, c := range cases {
		got := AppendVarInt(nil, c.v)
		if string(got) != string(c.want) {
			t.Fatalf("AppendVarInt(%d) = %x, want %x", c.v, got, c.want)
		}
		round, _, err := ReadVarInt(got)
		if err != nil {
			t.Fatalf("ReadVarInt round trip %d: %v", c.v, err)
		}
		if round != c.v {
			t.Fatalf("round trip mismatch: %d -> %x -> %d", c.v, got, round)
		}
	}
}

func TestAppendVarIntPanicsOnOverflow(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic on overflow")
		}
	}()
	_ = AppendVarInt(nil, 0x4000000000000000)
}

func TestVarIntLen(t *testing.T) {
	cases := []struct {
		v    uint64
		want int
	}{
		{0, 1},
		{0x3F, 1},
		{0x40, 2},
		{0x3FFF, 2},
		{0x4000, 4},
		{0x3FFFFFFF, 4},
		{0x40000000, 8},
		{0x3FFFFFFFFFFFFFFF, 8},
		{0x4000000000000000, 0},
	}
	for _, c := range cases {
		if got := VarIntLen(c.v); got != c.want {
			t.Fatalf("VarIntLen(%d) = %d, want %d", c.v, got, c.want)
		}
	}
}
