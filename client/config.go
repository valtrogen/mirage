package client

import (
	"crypto/tls"
	"errors"
	"time"

	utls "github.com/refraction-networking/utls"
)

// Config configures a mirage client Dial.
type Config struct {
	// ServerName is the SNI presented in the ClientHello. It must
	// match the server's TLS certificate.
	ServerName string

	// MasterKey is the 32-byte mirage master key shared with the
	// server. It is used to encrypt the per-connection session_id
	// embedded in the TLS legacy_session_id field.
	MasterKey [32]byte

	// ShortID is the 8-byte identifier carried inside the encrypted
	// session_id. The server resolves it to a UserID via its
	// configured authenticator.
	ShortID [8]byte

	// ClientHelloID selects the uTLS Chrome H3 fingerprint to mimic.
	// When zero, HelloChrome_120 is used.
	ClientHelloID utls.ClientHelloID

	// ALPN advertises the application protocol(s) in the
	// ClientHello. When empty, "h3" is used.
	ALPN []string

	// HandshakeTimeout caps the total time for the QUIC + TLS
	// handshake. When zero, 15 seconds is used.
	HandshakeTimeout time.Duration

	// IdleTimeout is the local idle timeout advertised to the server.
	// When zero, 30 seconds is used.
	IdleTimeout time.Duration

	// TLSConfig is the underlying TLS configuration. The ServerName
	// and NextProtos fields are overridden by ServerName and ALPN.
	// MinVersion is forced to TLS 1.3.
	TLSConfig *tls.Config
}

// Validate checks that c contains the fields required to dial.
func (c *Config) Validate() error {
	if c == nil {
		return errors.New("mirage/client: nil config")
	}
	if c.ServerName == "" {
		return errors.New("mirage/client: ServerName required")
	}
	if c.MasterKey == [32]byte{} {
		return errors.New("mirage/client: MasterKey required")
	}
	if c.ShortID == [8]byte{} {
		return errors.New("mirage/client: ShortID required")
	}
	return nil
}

func (c *Config) effectiveHelloID() utls.ClientHelloID {
	if c.ClientHelloID == (utls.ClientHelloID{}) {
		return utls.HelloChrome_120
	}
	return c.ClientHelloID
}

func (c *Config) effectiveALPN() []string {
	if len(c.ALPN) == 0 {
		return []string{"h3"}
	}
	return c.ALPN
}

func (c *Config) effectiveHandshakeTimeout() time.Duration {
	if c.HandshakeTimeout > 0 {
		return c.HandshakeTimeout
	}
	return 15 * time.Second
}

func (c *Config) effectiveIdleTimeout() time.Duration {
	if c.IdleTimeout > 0 {
		return c.IdleTimeout
	}
	return 30 * time.Second
}
