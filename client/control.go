package client

import (
	"io"

	"github.com/valtrogen/mirage/proto"
	"github.com/valtrogen/mirage/recycle"
)

// ReadControlFrame reads a single control frame from r. It returns the
// frame type and the body; the caller interprets the body according to
// the type. Unknown frame types are returned as-is per proto/frames.go:
// "Receivers must silently ignore unknown frame types."
//
// This is the client-side counterpart to recycle.WriteFrame. A typical
// client loop:
//
//	cs, _ := conn.AcceptStream(ctx) // first server-initiated stream
//	for {
//	    t, body, err := client.ReadControlFrame(cs)
//	    if err != nil { break }
//	    if t == proto.FrameTypeConnectionRecycleHint {
//	        hint, _ := recycle.DecodeHint(body)
//	        // migrate to new connection within hint.HandoffWindow
//	    }
//	}
func ReadControlFrame(r io.Reader) (proto.FrameType, []byte, error) {
	return recycle.ReadFrame(r)
}

// IsControlStream reports whether the stream ID is a server-initiated
// bidirectional stream that could be the control stream. Per proto/frames.go,
// control frames travel on a single bidi stream opened by the server.
// The first such stream has ID 1.
func IsControlStream(streamID uint64) bool {
	// QUIC stream ID bits: bit 0 = initiator (1=server), bit 1 = type (0=bidi).
	// Server-initiated bidirectional: 1, 5, 9, ...
	return streamID&0x03 == 0x01
}
