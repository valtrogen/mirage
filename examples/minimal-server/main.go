// minimal-server starts a mirage server on UDP/4433 with a self-signed
// cert, a static authenticator, and a static SNI relay pool. It echoes
// every byte received on each accepted stream back to the client.
//
// This is example code: do not use the self-signed cert or the hard
// coded master key in any environment that matters.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"io"
	"log"
	"math/big"
	"net"
	"time"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/handshake"
)

var (
	listen    = flag.String("listen", ":4433", "UDP listen address")
	sni       = flag.String("sni", "www.example.com", "TLS server name")
	upstream  = flag.String("relay", "1.1.1.1:443", "relay target host:port for unauthenticated traffic")
	masterHex = flag.String("master-key", "", "32-byte master key as hex; random if empty")
)

func main() {
	flag.Parse()

	pc, err := net.ListenPacket("udp", *listen)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	defer pc.Close()
	log.Printf("listening on %s", pc.LocalAddr())

	tlsConf := selfSigned(*sni)

	host, port, err := splitHostPort(*upstream)
	if err != nil {
		log.Fatalf("relay target: %v", err)
	}

	mk := make([]byte, 32)
	if *masterHex != "" {
		raw, err := hex.DecodeString(*masterHex)
		if err != nil || len(raw) != 32 {
			log.Fatalf("master-key: must be 64 hex chars")
		}
		copy(mk, raw)
	} else {
		if _, err := rand.Read(mk); err != nil {
			log.Fatalf("rand: %v", err)
		}
		log.Printf("master-key (random): %s", hex.EncodeToString(mk))
	}

	srv := &handshake.Server{
		PacketConn: pc,
		TLSConfig:  tlsConf,
		MasterKey:  mk,
		Authenticator: adapter.UserAuthenticatorFunc(func(_ context.Context, shortID []byte) (adapter.UserID, error) {
			if len(shortID) != 8 {
				return adapter.UserID{}, adapter.ErrUnknownUser
			}
			return adapter.UserID{1}, nil
		}),
		SNITargets: &adapter.StaticSNITargetProvider{Targets: map[string]adapter.StaticTarget{
			*sni: {Host: host, Port: port},
		}},
		SessionTTL: 5 * time.Minute,
	}
	if err := srv.Start(); err != nil {
		log.Fatalf("Start: %v", err)
	}
	defer srv.Close()

	for {
		conn, err := srv.Accept(context.Background())
		if err != nil {
			log.Printf("Accept: %v", err)
			return
		}
		go serve(conn)
	}
}

func serve(c *handshake.Conn) {
	defer c.CloseWithError(0, "")
	for {
		s, err := c.AcceptStream(context.Background())
		if err != nil {
			return
		}
		go func() {
			defer s.Close()
			_, _ = io.Copy(s, s)
		}()
	}
}

func selfSigned(name string) *tls.Config {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		log.Fatalf("genkey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		log.Fatalf("createcert: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		log.Fatalf("marshalkey: %v", err)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		log.Fatalf("keypair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}
}

func splitHostPort(s string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	pa, err := net.LookupPort("udp", portStr)
	if err != nil {
		return "", 0, err
	}
	return host, uint16(pa), nil
}
