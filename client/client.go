// Package client is the mirage QUIC client. It is a thin shim over
// quic-go's fork uquic that adds two things upstream cannot do alone:
//
//  1. Build the Chrome HTTP/3 ClientHello via uquic's QUICChrome_115
//     spec, including the random CRYPTO/PING/PADDING frame layout
//     Chrome emits in its first Initial packet.
//
//  2. Inject the encrypted short-id into the TLS legacy_session_id
//     extension after uTLS would otherwise zero it (RFC 9001 §8.4).
//     This is mirage's covert authentication channel — the server
//     dispatcher decides between "authenticated mirage traffic" and
//     "blind relay" by inspecting that one extension.
//
// Everything else (BBR-equivalent congestion control, flow control,
// packet retransmission, MTU discovery, key updates, stream cleanup,
// idle timeout) comes for free from upstream quic-go.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"time"

	uquic "github.com/refraction-networking/uquic"
	utlsfork "github.com/refraction-networking/utls"

	"github.com/valtrogen/mirage/behavior"
	"github.com/valtrogen/mirage/handshake"
	"github.com/valtrogen/mirage/proto"
	"github.com/valtrogen/mirage/replay"
)

// Config is the minimal set of knobs Dial needs. Anything not listed
// here is taken from the upstream quic-go defaults or the behavior
// package; callers that need finer control should construct a
// uquic.UTransport directly.
type Config struct {
	// ServerName is the SNI presented in the ClientHello.
	ServerName string

	// MasterKey is the 32-byte mirage master key shared with the server.
	MasterKey [32]byte

	// ShortID is the 8-byte identifier carried inside the encrypted
	// session_id.
	ShortID [8]byte

	// HandshakeTimeout caps the time the QUIC + TLS handshake is
	// allowed to take. Zero means 15 seconds.
	HandshakeTimeout time.Duration

	// IdleTimeout is the local idle timeout. Zero means 30 seconds.
	IdleTimeout time.Duration

	// InsecureSkipVerify disables TLS verification. Only useful in
	// loopback / testbed deployments where the server presents a
	// self-signed cert.
	InsecureSkipVerify bool

	// RootCAs supplies an alternate trust store. When nil, the system
	// trust store is used. Only the RootCAs and ServerName fields are
	// read; everything else is overridden by mirage-specific values.
	RootCAs *tls.Config
}

func (c *Config) handshakeTimeout() time.Duration {
	if c.HandshakeTimeout > 0 {
		return c.HandshakeTimeout
	}
	return 15 * time.Second
}

func (c *Config) idleTimeout() time.Duration {
	if c.IdleTimeout > 0 {
		return c.IdleTimeout
	}
	return 30 * time.Second
}

func (c *Config) validate() error {
	if c == nil {
		return errors.New("mirage/client: nil config")
	}
	if c.ServerName == "" {
		return errors.New("mirage/client: ServerName required")
	}
	if c.MasterKey == ([32]byte{}) {
		return errors.New("mirage/client: MasterKey required")
	}
	if c.ShortID == ([8]byte{}) {
		return errors.New("mirage/client: ShortID required")
	}
	return nil
}

// Conn is a connected mirage client. It wraps a uquic Connection.
type Conn struct {
	qc uquic.Connection

	tr *uquic.UTransport

	// pconn is the underlying UDP socket so Close releases it.
	pconn net.PacketConn
}

// Dial opens one mirage connection to addr (host:port).
func Dial(ctx context.Context, addr string, cfg *Config) (*Conn, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}

	udpAddr, err := net.ResolveUDPAddr("udp", addr)
	if err != nil {
		return nil, fmt.Errorf("mirage/client: resolve %s: %w", addr, err)
	}
	pconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return nil, fmt.Errorf("mirage/client: bind UDP: %w", err)
	}

	sid, err := encodedSessionID(cfg)
	if err != nil {
		_ = pconn.Close()
		return nil, err
	}

	spec, err := uquic.QUICID2Spec(uquic.QUICChrome_115)
	if err != nil {
		_ = pconn.Close()
		return nil, fmt.Errorf("mirage/client: load Chrome QUIC spec: %w", err)
	}
	spec.PostApplyPreset = func(uqc *utlsfork.UQUICConn) error {
		return injectSessionID(uqc, sid[:])
	}

	tlsConf := &utlsfork.Config{
		ServerName:         cfg.ServerName,
		NextProtos:         []string{"h3"},
		MinVersion:         utlsfork.VersionTLS13,
		MaxVersion:         utlsfork.VersionTLS13,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}
	if cfg.RootCAs != nil && cfg.RootCAs.RootCAs != nil {
		tlsConf.RootCAs = cfg.RootCAs.RootCAs
	}

	// Flow-control windows must match what uquic advertises in the
	// Chrome H3 TLS transport parameters; otherwise the server sends
	// up to the advertised limit and quic-go's internal accounting
	// trips FLOW_CONTROL_ERROR. Pull the numbers from behavior so
	// the two sources cannot drift.
	bh := behavior.Default()
	qcfg := &uquic.Config{
		HandshakeIdleTimeout:           cfg.handshakeTimeout(),
		MaxIdleTimeout:                 cfg.idleTimeout(),
		KeepAlivePeriod:                cfg.idleTimeout() / 3,
		InitialStreamReceiveWindow:     bh.InitialMaxStreamDataBidiLocal,
		MaxStreamReceiveWindow:         bh.MaxStreamReceiveWindow,
		InitialConnectionReceiveWindow: bh.InitialMaxData,
		MaxConnectionReceiveWindow:     bh.MaxConnectionReceiveWindow,
		MaxIncomingStreams:             int64(bh.InitialMaxStreamsBidi),
		MaxIncomingUniStreams:          int64(bh.InitialMaxStreamsUni),
	}

	tr := &uquic.UTransport{
		Transport: &uquic.Transport{Conn: pconn},
		QUICSpec:  &spec,
	}

	dialCtx, cancel := context.WithTimeout(ctx, cfg.handshakeTimeout())
	defer cancel()

	qc, err := tr.Dial(dialCtx, udpAddr, tlsConf, qcfg)
	if err != nil {
		_ = tr.Close()
		_ = pconn.Close()
		return nil, fmt.Errorf("mirage/client: handshake: %w", err)
	}
	return &Conn{qc: qc, tr: tr, pconn: pconn}, nil
}

// Close tears down the connection and releases the UDP socket.
func (c *Conn) Close() error {
	if c == nil {
		return nil
	}
	if c.qc != nil {
		_ = c.qc.CloseWithError(0, "mirage/client: shutdown")
	}
	if c.tr != nil {
		_ = c.tr.Close()
	}
	if c.pconn != nil {
		return c.pconn.Close()
	}
	return nil
}

// LocalAddr returns the local UDP address.
func (c *Conn) LocalAddr() net.Addr {
	if c == nil || c.pconn == nil {
		return nil
	}
	return c.pconn.LocalAddr()
}

// OpenStream opens a bidirectional stream and returns it as the
// package's Stream interface. proxy.Dial consumes this.
func (c *Conn) OpenStream(ctx context.Context) (Stream, error) {
	if c == nil || c.qc == nil {
		return nil, errors.New("mirage/client: nil Conn")
	}
	st, err := c.qc.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	return &stream{Stream: st}, nil
}

// encodedSessionID builds the 32-byte legacy_session_id payload mirage
// servers verify.
func encodedSessionID(cfg *Config) (sid [proto.SessionIDLen]byte, err error) {
	wid := replay.CurrentWindowID()
	wkey, err := replay.DeriveWindowKey(cfg.MasterKey[:], wid)
	if err != nil {
		return sid, fmt.Errorf("mirage/client: derive window key: %w", err)
	}
	if err := handshake.EncodeSessionID(sid[:], wkey, cfg.ShortID[:], wid); err != nil {
		return sid, fmt.Errorf("mirage/client: encode session id: %w", err)
	}
	return sid, nil
}
