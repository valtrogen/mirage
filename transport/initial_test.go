package transport

import (
	"bytes"
	"encoding/hex"
	"strings"
	"testing"
)

// rfcInitialPacketHex is the encrypted client Initial packet from RFC 9001
// Appendix A.2. It carries a single CRYPTO frame followed by PADDING and
// fits in a 1200-byte UDP datagram.
const rfcInitialPacketHex = `
c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11
d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399
1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c
8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212
30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5
457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208
4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec
4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3
485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db
059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c
7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8
9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556
be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74
68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a
c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00
f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632
291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964
25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd
14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff
ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198
e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd
c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73
203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f
cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e
fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade
a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047
90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2
162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4
40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0
6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e
8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0
be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400
54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab
760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9
f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4
056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064
7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241
e221af44860018ab0856972e194cd934
`

func rfcInitialPacket(t *testing.T) []byte {
	t.Helper()
	clean := strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, rfcInitialPacketHex)
	b, err := hex.DecodeString(clean)
	if err != nil {
		t.Fatalf("hex decode: %v", err)
	}
	if len(b) != 1200 {
		t.Fatalf("RFC vector should be 1200 bytes, got %d", len(b))
	}
	return b
}

// mustHex decodes a hex string and fails the test on error. Used by
// the RFC 9001 vector assertions; kept private to the test file.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex %q: %v", s, err)
	}
	return b
}

func TestParseInitialRFCVector(t *testing.T) {
	pkt := rfcInitialPacket(t)
	got, err := ParseInitial(pkt)
	if err != nil {
		t.Fatalf("ParseInitial: %v", err)
	}

	if got.Version != QUICv1 {
		t.Fatalf("version: got %x", got.Version)
	}
	if !bytes.Equal(got.DCID, mustHex(t, "8394c8f03e515708")) {
		t.Fatalf("DCID: got %x", got.DCID)
	}
	if len(got.SCID) != 0 {
		t.Fatalf("SCID: got %x, want empty", got.SCID)
	}
	if len(got.Token) != 0 {
		t.Fatalf("Token: got %x, want empty", got.Token)
	}
	if got.PacketNumber != 2 {
		t.Fatalf("packet number: got %d, want 2", got.PacketNumber)
	}
	if got.PacketLen != 1200 {
		t.Fatalf("packet len: got %d, want 1200", got.PacketLen)
	}

	if len(got.Payload) < 4 {
		t.Fatalf("plaintext too short: %d", len(got.Payload))
	}
	if got.Payload[0] != 0x06 || got.Payload[1] != 0x00 ||
		got.Payload[2] != 0x40 || got.Payload[3] != 0xF1 {
		t.Fatalf("unexpected CRYPTO header: % x", got.Payload[:4])
	}

	ch, err := ExtractCRYPTOData(got.Payload)
	if err != nil {
		t.Fatalf("ExtractCRYPTOData: %v", err)
	}
	if len(ch) != 241 {
		t.Fatalf("ClientHello length: got %d, want 241", len(ch))
	}
	if ch[0] != 0x01 || ch[1] != 0x00 || ch[2] != 0x00 || ch[3] != 0xED {
		t.Fatalf("not a ClientHello: % x", ch[:4])
	}
}

func TestParseInitialRejectsNonInitial(t *testing.T) {
	cases := [][]byte{
		nil,
		{0x00, 0x00},
		bytes.Repeat([]byte{0x40}, 64),
		append([]byte{0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, bytes.Repeat([]byte{0xAA}, 64)...),
		append([]byte{0xE0, 0x00, 0x00, 0x00, 0x01}, bytes.Repeat([]byte{0xAA}, 64)...),
	}
	for i, c := range cases {
		_, err := ParseInitial(c)
		if err == nil {
			t.Fatalf("case %d: want error, got nil", i)
		}
	}
}

func TestParseInitialBadAuthTag(t *testing.T) {
	pkt := rfcInitialPacket(t)
	pkt[len(pkt)-1] ^= 0x01
	if _, err := ParseInitial(pkt); err != ErrAEADAuthFailed {
		t.Fatalf("want ErrAEADAuthFailed, got %v", err)
	}
}

func TestExtractCRYPTODataSkipsPaddingAndPing(t *testing.T) {
	payload := []byte{0x00, 0x00, 0x06, 0x00, 0x04, 'A', 'B', 'C', 'D', 0x01, 0x00}
	got, err := ExtractCRYPTOData(payload)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(got) != "ABCD" {
		t.Fatalf("got %q", got)
	}
}

func TestExtractCRYPTODataStopsOnGap(t *testing.T) {
	payload := []byte{0x06, 0x05, 0x02, 'X', 'Y'}
	got, err := ExtractCRYPTOData(payload)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("want empty, got %q", got)
	}
}

// TestExtractCRYPTODataShuffledChromeStyle exercises the layout uquic's
// QUICRandomFrames builder produces for the Chrome H3 parrot: the
// ClientHello is split across several CRYPTO frames at increasing
// offsets and then the entire list (including PING + PADDING) is
// shuffled. The dispatcher must still recover the original byte
// stream.
func TestExtractCRYPTODataShuffledChromeStyle(t *testing.T) {
	hello := []byte("CLIENTHELLO-PAYLOAD-CHROMESTYLE-CRYPTO-DATA-1234567890")

	// Build CRYPTO fragments for [0:10), [10:25), [25:len(hello)) but
	// emit them in 2,0,1 order with PING and PADDING sprinkled in.
	frag := func(off uint64, lo, hi int) []byte {
		buf := []byte{0x06}
		buf = AppendVarInt(buf, off)
		buf = AppendVarInt(buf, uint64(hi-lo))
		buf = append(buf, hello[lo:hi]...)
		return buf
	}

	var payload []byte
	payload = append(payload, 0x01) // PING
	payload = append(payload, frag(25, 25, len(hello))...)
	payload = append(payload, 0x00, 0x00, 0x00) // PADDING
	payload = append(payload, frag(0, 0, 10)...)
	payload = append(payload, 0x01) // PING
	payload = append(payload, frag(10, 10, 25)...)
	payload = append(payload, 0x00, 0x00) // trailing PADDING

	got, err := ExtractCRYPTOData(payload)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Fatalf("reassembly mismatch:\n got=%q\nwant=%q", got, hello)
	}
}

// TestExtractCRYPTODataDuplicateFragments confirms the reassembler
// tolerates retransmitted CRYPTO fragments: an exact duplicate of
// [10:25) before the canonical [10:25) must not corrupt the output.
func TestExtractCRYPTODataDuplicateFragments(t *testing.T) {
	hello := []byte("ABCDEFGHIJKLMNOPQRSTUVWXYZ")

	frag := func(off uint64, lo, hi int) []byte {
		buf := []byte{0x06}
		buf = AppendVarInt(buf, off)
		buf = AppendVarInt(buf, uint64(hi-lo))
		return append(buf, hello[lo:hi]...)
	}

	var payload []byte
	payload = append(payload, frag(0, 0, 10)...)
	payload = append(payload, frag(10, 10, 20)...)
	payload = append(payload, frag(10, 10, 20)...) // dup
	payload = append(payload, frag(20, 20, len(hello))...)

	got, err := ExtractCRYPTOData(payload)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(got, hello) {
		t.Fatalf("got %q want %q", got, hello)
	}
}

// TestExtractCRYPTODataSkipsACK exercises the ACK skipping path: a
// CRYPTO frame followed by an ACK and another CRYPTO frame must not
// abort reassembly mid-stream.
func TestExtractCRYPTODataSkipsACK(t *testing.T) {
	frag := func(off uint64, b []byte) []byte {
		buf := []byte{0x06}
		buf = AppendVarInt(buf, off)
		buf = AppendVarInt(buf, uint64(len(b)))
		return append(buf, b...)
	}

	var payload []byte
	payload = append(payload, frag(0, []byte("AAAA"))...)

	// ACK frame: type=0x02, largest=10, delay=0, range count=0,
	// first range=10. All single-byte varints.
	payload = append(payload, 0x02, 0x0A, 0x00, 0x00, 0x0A)

	payload = append(payload, frag(4, []byte("BBBB"))...)

	got, err := ExtractCRYPTOData(payload)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if string(got) != "AAAABBBB" {
		t.Fatalf("got %q want AAAABBBB", got)
	}
}
