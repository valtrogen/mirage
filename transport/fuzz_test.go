package transport

import "testing"

// FuzzParseFrames feeds arbitrary byte strings to ParseFrames. The
// invariant the corpus enforces is "no panic, no infinite loop" — the
// parser is permitted to return an error for any input but must never
// crash, leak garbage frames after an error, or loop forever.
//
// Run as `go test -run=^$ -fuzz=FuzzParseFrames ./transport/...`.
// The unattended `go test` invocation only executes the seed corpus.
func FuzzParseFrames(f *testing.F) {
	// Hand-curated seeds covering well-formed frames and tricky
	// truncation points. Each one exercises a distinct frame-type
	// branch in ParseFrames so the fuzzer can mutate around known
	// shapes rather than starting from zero.
	seeds := [][]byte{
		AppendCryptoFrame(nil, 0, []byte("client hello bytes")),
		AppendAckFrame(nil, 5, 0, 1),
		AppendAckFrameRanges(nil, 0, []uint64{10, 9, 5, 4}),
		AppendStreamFrame(nil, 0, 0, []byte("ping"), false),
		AppendStreamFrame(nil, 1, 16, []byte("frag"), true),
		AppendMaxDataFrame(nil, 1<<20),
		AppendMaxStreamDataFrame(nil, 4, 1<<19),
		AppendResetStreamFrame(nil, 4, 0x10, 1024),
		AppendStopSendingFrame(nil, 4, 0x10),
		AppendRetireConnectionIDFrame(nil, 7),
		AppendConnectionCloseFrame(nil, 0x100, 0, "bye"),
		AppendPingFrame(nil),
		{0x18, 0x01, 0x00, 0x04, 0xAA, 0xBB, 0xCC, 0xDD, // NEW_CONNECTION_ID
			0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE,
			0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE, 0xFE},
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		// We deliberately ignore both return values: the contract is
		// that ParseFrames returns OR returns an error, not that it
		// produces meaningful output for adversarial input.
		_, _ = ParseFrames(data)
	})
}
