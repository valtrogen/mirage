package client

import (
	"io"
	"time"

	uquic "github.com/refraction-networking/uquic"
)

// Stream is the minimal interface client.OpenStream returns. It is
// the same shape proxy.Dial expects (io.ReadWriteCloser + deadlines)
// so the framing layer does not depend on uquic types directly.
type Stream interface {
	io.ReadWriteCloser
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

// stream adapts a uquic.Stream to the package's Stream interface.
type stream struct {
	uquic.Stream
}

func (s *stream) SetDeadline(t time.Time) error      { return s.Stream.SetDeadline(t) }
func (s *stream) SetReadDeadline(t time.Time) error  { return s.Stream.SetReadDeadline(t) }
func (s *stream) SetWriteDeadline(t time.Time) error { return s.Stream.SetWriteDeadline(t) }
