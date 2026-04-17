package client

import (
	"crypto/tls"

	utls "github.com/refraction-networking/utls"
)

// translateTLSConfig copies the fields mirage cares about from a
// crypto/tls Config into a utls Config. uTLS reuses the same field
// shape for most TLS knobs, so a shallow copy is sufficient.
func translateTLSConfig(in *tls.Config) *utls.Config {
	if in == nil {
		return &utls.Config{MinVersion: utls.VersionTLS13}
	}
	out := &utls.Config{
		ServerName:         in.ServerName,
		NextProtos:         in.NextProtos,
		InsecureSkipVerify: in.InsecureSkipVerify,
		RootCAs:            in.RootCAs,
		MinVersion:         utls.VersionTLS13,
		MaxVersion:         utls.VersionTLS13,
		KeyLogWriter:       in.KeyLogWriter,
	}
	return out
}
