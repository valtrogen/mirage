package transport

import (
	"bytes"
	"testing"
)

// buildHandshake assembles a minimal TLS 1.3 Handshake(ClientHello) record
// containing only the fields ExtractClientHelloSessionID needs to inspect.
// extra is appended after legacy_session_id so callers can attach valid
// or padding bytes; ExtractClientHelloSessionID never reads past
// session_id, so its content is irrelevant.
func buildHandshake(t *testing.T, sid []byte, extra []byte) []byte {
	t.Helper()
	if len(sid) > 32 {
		t.Fatalf("sid too long")
	}

	var body bytes.Buffer
	body.Write([]byte{0x03, 0x03})
	var random [32]byte
	for i := range random {
		random[i] = byte(i)
	}
	body.Write(random[:])
	body.WriteByte(byte(len(sid)))
	body.Write(sid)
	body.Write(extra)

	out := make([]byte, 4+body.Len())
	out[0] = 0x01
	out[1] = byte(body.Len() >> 16)
	out[2] = byte(body.Len() >> 8)
	out[3] = byte(body.Len())
	copy(out[4:], body.Bytes())
	return out
}

func TestExtractClientHelloSessionIDEmpty(t *testing.T) {
	hs := buildHandshake(t, nil, nil)
	got, err := ExtractClientHelloSessionID(hs)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("got %x, want empty", got)
	}
}

func TestExtractClientHelloSessionIDFull32(t *testing.T) {
	want := bytes.Repeat([]byte{0xAB}, 32)
	hs := buildHandshake(t, want, []byte{0xCC, 0xDD, 0xEE})
	got, err := ExtractClientHelloSessionID(hs)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestExtractClientHelloSessionIDRejectsWrongType(t *testing.T) {
	hs := buildHandshake(t, nil, nil)
	hs[0] = 0x02
	if _, err := ExtractClientHelloSessionID(hs); err != ErrNotClientHello {
		t.Fatalf("want ErrNotClientHello, got %v", err)
	}
}

func TestExtractClientHelloSessionIDRejectsTruncated(t *testing.T) {
	hs := buildHandshake(t, []byte{1, 2, 3, 4, 5}, nil)
	for cut := 0; cut < 35+5; cut++ {
		if _, err := ExtractClientHelloSessionID(hs[:cut]); err == nil {
			t.Fatalf("cut=%d: want error, got nil", cut)
		}
	}
}

func TestExtractClientHelloSessionIDRejectsOversizeSID(t *testing.T) {
	hs := buildHandshake(t, nil, nil)
	// Patch session_id length byte to 33 (illegal per RFC 8446).
	hs[4+34] = 33
	if _, err := ExtractClientHelloSessionID(hs); err != ErrTruncatedClientHello {
		t.Fatalf("want ErrTruncatedClientHello, got %v", err)
	}
}

func TestExtractClientHelloSessionIDRejectsBodyShorterThanDeclared(t *testing.T) {
	hs := buildHandshake(t, []byte{0xAA, 0xBB}, nil)
	// Inflate declared length so body claims to be 1000 bytes.
	hs[1] = 0x00
	hs[2] = 0x03
	hs[3] = 0xE8
	if _, err := ExtractClientHelloSessionID(hs); err != ErrTruncatedClientHello {
		t.Fatalf("want ErrTruncatedClientHello, got %v", err)
	}
}
