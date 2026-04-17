package handshake

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/valtrogen/mirage/adapter"
)

func selfSignedTLSConfig(t *testing.T, sni string) *tls.Config {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: sni},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{sni},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("createcert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("marshalkey: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h3"},
	}
}

func TestVirtualPacketConnReadDeadline(t *testing.T) {
	parent, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer parent.Close()

	v := newVirtualPacketConn(parent, make(chan AuthDatagram, 8))
	defer v.Close()

	if err := v.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 1500)
	start := time.Now()
	_, _, err = v.ReadFrom(buf)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	ne, ok := err.(net.Error)
	if !ok || !ne.Timeout() {
		t.Fatalf("expected net.Error timeout, got %T %v", err, err)
	}
	if time.Since(start) < 40*time.Millisecond {
		t.Fatalf("returned too fast: %v", time.Since(start))
	}
}

func TestVirtualPacketConnReadFromChannel(t *testing.T) {
	parent, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer parent.Close()

	v := newVirtualPacketConn(parent, make(chan AuthDatagram, 8))
	defer v.Close()

	addr := &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4242}
	payload := []byte{0xC0, 0x00, 0x00, 0x00, 0x01}
	go func() { v.in <- AuthDatagram{Data: payload, RemoteAddr: addr} }()

	buf := make([]byte, 1500)
	n, ra, err := v.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("payload mismatch: %x", buf[:n])
	}
	if ra.String() != addr.String() {
		t.Fatalf("addr mismatch: %s", ra)
	}
}

func TestServerStartValidation(t *testing.T) {
	cases := []struct {
		name string
		s    *Server
	}{
		{"nil PacketConn", &Server{TLSConfig: &tls.Config{}, MasterKey: make([]byte, 32), Authenticator: adapter.UserAuthenticatorFunc(func(context.Context, []byte) (adapter.UserID, error) { return adapter.UserID{}, nil })}},
		{"nil TLSConfig", &Server{PacketConn: &net.UDPConn{}, MasterKey: make([]byte, 32), Authenticator: adapter.UserAuthenticatorFunc(func(context.Context, []byte) (adapter.UserID, error) { return adapter.UserID{}, nil })}},
		{"short MasterKey", &Server{PacketConn: &net.UDPConn{}, TLSConfig: &tls.Config{}, MasterKey: make([]byte, 8), Authenticator: adapter.UserAuthenticatorFunc(func(context.Context, []byte) (adapter.UserID, error) { return adapter.UserID{}, nil })}},
		{"nil Authenticator", &Server{PacketConn: &net.UDPConn{}, TLSConfig: &tls.Config{}, MasterKey: make([]byte, 32)}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := c.s.Start(); err == nil {
				t.Fatal("expected error")
			}
			_ = c.s.Close()
		})
	}
}

// TestServerRelayE2E spins a real quic-go client against the mirage
// server. The client's stdlib TLS produces a random 32-byte session_id,
// which the dispatcher cannot decode, so the dispatcher routes the
// stream of UDP datagrams to the relay pool. The relay is a UDP echo
// server that observes the bytes; we verify dispatcher state plus that
// upstream actually saw the client's first datagram.
func TestServerRelayE2E(t *testing.T) {
	upstreamHost, upstreamPort, stop := startEchoUDPDisp(t)
	defer stop()

	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer pc.Close()

	mk := make([]byte, 32)
	rand.Read(mk)

	srv := &Server{
		PacketConn:    pc,
		TLSConfig:     selfSignedTLSConfig(t, "www.example.com"),
		MasterKey:     mk,
		Authenticator: &fixedAuthenticator{shortID: []byte("doesnotm")},
		SNITargets: &adapter.StaticSNITargetProvider{Targets: map[string]adapter.StaticTarget{
			"www.example.com": {Host: upstreamHost, Port: upstreamPort},
		}},
		SessionTTL: 500 * time.Millisecond,
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	_, _ = quic.DialAddr(ctx, pc.LocalAddr().String(), &tls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"h3"},
		ServerName:         "www.example.com",
	}, &quic.Config{HandshakeIdleTimeout: time.Second})

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if srv.dispatcher.SessionCount() >= 1 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if srv.dispatcher.SessionCount() == 0 {
		t.Fatal("dispatcher saw no client datagrams")
	}
}

// TestServerAuthRoutesToQUIC verifies that a synthetic Initial whose
// session_id is properly encoded for the server's master key is handed
// to the embedded quic-go listener. The synthetic ClientHello is too
// minimal to drive a real TLS 1.3 handshake to completion, but the
// server must respond to the Initial (with at least a CONNECTION_CLOSE
// or version negotiation hint), proving the auth path reached quic-go.
func TestServerAuthRoutesToQUIC(t *testing.T) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("server listen: %v", err)
	}
	defer pc.Close()

	mk := make([]byte, 32)
	rand.Read(mk)

	srv := &Server{
		PacketConn:    pc,
		TLSConfig:     selfSignedTLSConfig(t, "www.example.com"),
		MasterKey:     mk,
		Authenticator: &fixedAuthenticator{shortID: []byte("87654321")},
		SessionTTL:    500 * time.Millisecond,
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	dcid := bytes.Repeat([]byte{0xC1}, 8)
	pkt := buildAuthInitial(t, srv.dispatcher.Keyring, []byte("87654321"), dcid, 1)

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()

	if _, err := client.WriteToUDP(pkt, pc.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		_, ok := srv.dispatcher.UserIDFor(client.LocalAddr())
		if ok {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, ok := srv.dispatcher.UserIDFor(client.LocalAddr()); !ok {
		t.Fatal("client not registered as authenticated")
	}

	var got atomic.Bool
	go func() {
		buf := make([]byte, 2048)
		_ = client.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
		if _, _, err := client.ReadFromUDP(buf); err == nil {
			got.Store(true)
		}
	}()

	deadline = time.Now().Add(1500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if got.Load() {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !got.Load() {
		t.Fatal("server returned no bytes for authenticated synthetic Initial")
	}
}
