package client_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/client"
	"github.com/valtrogen/mirage/handshake"
)

func selfSignedTLS(t *testing.T, sni string) *tls.Config {
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

// TestClientHandshakeAgainstServer dials a real mirage server with the
// mirage client and verifies the QUIC + TLS handshake completes. The
// server's authenticator records that the expected short-id was
// presented. The data plane (streams) is exercised by a separate test
// once the stream API lands.
func TestClientHandshakeAgainstServer(t *testing.T) {
	if testing.Short() {
		t.Skip("integration handshake")
	}

	pconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pconn.Close()

	var masterKey [32]byte
	copy(masterKey[:], []byte("mirage-test-master-key-32-bytes!!"))
	shortID := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	wantUID := adapter.UserID{0xAA, 0xBB, 0xCC, 0xDD}

	var seenShortID atomic.Value
	auth := adapter.UserAuthenticatorFunc(func(_ context.Context, sid []byte) (adapter.UserID, error) {
		cp := append([]byte(nil), sid...)
		seenShortID.Store(cp)
		return wantUID, nil
	})

	srv := &handshake.Server{
		PacketConn:    pconn,
		TLSConfig:     selfSignedTLS(t, "example.test"),
		MasterKey:     masterKey[:],
		Authenticator: auth,
		QUICConfig:    &quic.Config{HandshakeIdleTimeout: 5 * time.Second},
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("server start: %v", err)
	}
	defer srv.Close()

	var serverErr atomic.Value
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()
		c, err := srv.Accept(ctx)
		if err != nil {
			serverErr.Store(err)
			return
		}
		defer c.CloseWithError(0, "")
		if c.UserID != wantUID {
			serverErr.Store(errors.New("unexpected UserID"))
		}
	}()

	cli, err := client.Dial(context.Background(), pconn.LocalAddr().String(), &client.Config{
		ServerName: "example.test",
		MasterKey:  masterKey,
		ShortID:    shortID,
		ALPN:       []string{"h3"},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
		HandshakeTimeout: 6 * time.Second,
	})
	if err != nil {
		t.Fatalf("client dial: %v", err)
	}
	defer cli.Close()

	if !cli.HandshakeComplete() {
		t.Fatal("client handshake not marked complete")
	}

	wg.Wait()
	if v := serverErr.Load(); v != nil {
		t.Fatalf("server side: %v", v.(error))
	}

	v := seenShortID.Load()
	if v == nil {
		t.Fatal("server authenticator never invoked")
	}
	got := v.([]byte)
	if string(got) != string(shortID[:]) {
		t.Fatalf("server saw short-id %x want %x", got, shortID[:])
	}
}
