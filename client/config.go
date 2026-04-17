package client

import (
	"crypto/tls"
	"errors"
	"time"

	utls "github.com/refraction-networking/utls"

	"github.com/valtrogen/mirage/behavior"
	"github.com/valtrogen/mirage/padder"
	"github.com/valtrogen/mirage/recycle"
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

	// Behavior is the data-plane stealth profile mirage matches against:
	// PING interval, ACK delay, and other timing-driven defaults that
	// would otherwise expose mirage as non-Chrome to a flow timing
	// classifier. The zero value uses behavior.Default().
	Behavior behavior.ChromeH3

	// PadderPolicy governs idle-period keepalive padding. The padder
	// injects small random-payload packets during application idle
	// gaps when the congestion controller is in a bandwidth-spare
	// phase (ProbeRTT). This breaks the "long silent gaps followed by
	// sudden bursts" pattern that distinguishes proxy flows from real
	// Chrome traffic. The zero value uses padder.Default(); set
	// DisablePadder to opt out entirely.
	PadderPolicy padder.Policy

	// DisablePadder disables the padder regardless of PadderPolicy.
	// Use this in benchmarks and tests where deterministic byte
	// accounting is more important than the stealth posture.
	DisablePadder bool

	// OnRecycleHint, if non-nil, is invoked exactly once on a
	// background goroutine when the server signals that this
	// connection is past its operational threshold and should be
	// rotated out within hint.HandoffWindow. The integration is
	// expected to dial a fresh connection, route new traffic to it,
	// and let the old connection drain.
	//
	// Setting this field opts the client into auto-dispatching the
	// first server-initiated bidirectional stream as the mirage
	// control stream; that stream becomes invisible to AcceptStream.
	OnRecycleHint func(recycle.Hint)
}

// effectiveBehavior returns Behavior, or behavior.Default() if the
// caller left the field zero-valued.
func (c *Config) effectiveBehavior() behavior.ChromeH3 {
	if c.Behavior == (behavior.ChromeH3{}) {
		return behavior.Default()
	}
	return c.Behavior
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

func (c *Config) effectivePadderPolicy() padder.Policy {
	if c.DisablePadder {
		return padder.Policy{} // IdleAfter==0 disables the Padder
	}
	if c.PadderPolicy != (padder.Policy{}) {
		return c.PadderPolicy
	}
	return padder.Default()
}

