package recycle

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/valtrogen/mirage/proto"
)

// DefaultHandoffWindow is the recommended grace window during which the
// server keeps accepting new streams after sending the recycle hint.
// Real flows usually finish within a handful of seconds; 30s gives the
// client comfortable headroom to dial a fresh connection and migrate
// pending streams.
const DefaultHandoffWindow = 30 * time.Second

// Hint is the decoded body of a ConnectionRecycleHint frame.
type Hint struct {
	HandoffWindow time.Duration
}

// ErrHintBodyLen is returned when the hint body is not exactly two
// bytes long.
var ErrHintBodyLen = errors.New("mirage/recycle: ConnectionRecycleHint body must be 2 bytes")

// EncodeHint serialises h's HandoffWindow to a 2-byte big-endian
// millisecond value. Values above 65535ms are clamped.
func EncodeHint(h Hint) []byte {
	ms := h.HandoffWindow / time.Millisecond
	if ms < 0 {
		ms = 0
	}
	if ms > 0xFFFF {
		ms = 0xFFFF
	}
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], uint16(ms))
	return b[:]
}

// DecodeHint inverts EncodeHint.
func DecodeHint(body []byte) (Hint, error) {
	if len(body) != 2 {
		return Hint{}, ErrHintBodyLen
	}
	return Hint{HandoffWindow: time.Duration(binary.BigEndian.Uint16(body)) * time.Millisecond}, nil
}

// ErrFrameTooLarge is returned when a body exceeds proto.MaxFrameBodyLen.
var ErrFrameTooLarge = fmt.Errorf("mirage/recycle: frame body exceeds %d bytes", proto.MaxFrameBodyLen)

// WriteFrame writes a control-stream frame with the given type and
// body. The frame layout is Type(1) | Length(BE16) | Body.
func WriteFrame(w io.Writer, t proto.FrameType, body []byte) error {
	if len(body) > proto.MaxFrameBodyLen {
		return ErrFrameTooLarge
	}
	hdr := [proto.FrameHeaderLen]byte{byte(t), byte(len(body) >> 8), byte(len(body))}
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(body) == 0 {
		return nil
	}
	_, err := w.Write(body)
	return err
}

// ReadFrame reads one control-stream frame from r. It returns the type
// and the body slice (which is freshly allocated).
func ReadFrame(r io.Reader) (proto.FrameType, []byte, error) {
	var hdr [proto.FrameHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	bodyLen := int(binary.BigEndian.Uint16(hdr[1:3]))
	if bodyLen == 0 {
		return proto.FrameType(hdr[0]), nil, nil
	}
	body := make([]byte, bodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, err
	}
	return proto.FrameType(hdr[0]), body, nil
}

// WriteHint is a convenience for the common case of sending a
// ConnectionRecycleHint frame.
func WriteHint(w io.Writer, h Hint) error {
	return WriteFrame(w, proto.FrameTypeConnectionRecycleHint, EncodeHint(h))
}
