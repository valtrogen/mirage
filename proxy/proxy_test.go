package proxy_test

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
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/client"
	"github.com/valtrogen/mirage/handshake"
	"github.com/valtrogen/mirage/metrics"
	"github.com/valtrogen/mirage/proxy"
)

const testSNI = "proxy.test"

func TestProxyEndToEndTCPEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	echo := startTCPEchoServer(t)
	defer echo.Close()

	srv, mc := startMiragePair(t, nil, nil)
	defer mc.Close()

	upstream, err := proxy.Dial(testCtx(t, 5*time.Second), mc, "tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("proxy.Dial: %v", err)
	}
	defer upstream.Close()

	payload := []byte("hello mirage proxy")
	if _, err := upstream.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := readN(t, upstream, len(payload))
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got=%q want=%q", got, payload)
	}

	if err := upstream.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	srv.shutdown(t)
}

func TestProxyDialMultipleStreamsOnOneConn(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	echo := startTCPEchoServer(t)
	defer echo.Close()

	srv, mc := startMiragePair(t, nil, nil)
	defer mc.Close()

	const N = 4
	var wg sync.WaitGroup
	wg.Add(N)
	errs := make(chan error, N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			conn, err := proxy.Dial(testCtx(t, 5*time.Second), mc, "tcp", echo.Addr().String())
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			payload := []byte{byte('A' + i), byte('A' + i), byte('A' + i)}
			if _, err := conn.Write(payload); err != nil {
				errs <- err
				return
			}
			got := readN(t, conn, len(payload))
			if string(got) != string(payload) {
				errs <- errors.New("echo mismatch")
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("stream: %v", err)
	}
	srv.shutdown(t)
}

func TestProxyDialDeniedReturnsError(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	authz := adapter.ProxyAuthorizerFunc(func(_ context.Context, _ adapter.UserID, _ string, _ uint16) error {
		return errors.New("nope")
	})
	srv, mc := startMiragePair(t, authz, nil)
	defer mc.Close()

	_, err := proxy.Dial(testCtx(t, 3*time.Second), mc, "tcp", "192.0.2.1:443")
	if err == nil {
		t.Fatal("Dial succeeded; want denial")
	}
	var pe *proxy.Error
	if !errors.As(err, &pe) {
		t.Fatalf("err type %T (%v)", err, err)
	}
	if pe.Status != proxy.StatusNotAllowed {
		t.Fatalf("status=%v want NotAllowed", pe.Status)
	}
	if !strings.Contains(pe.Reason, "nope") {
		t.Fatalf("reason=%q", pe.Reason)
	}
	srv.shutdown(t)
}

func TestProxyDialUnreachableTargetReturnsConnRefused(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	srv, mc := startMiragePair(t, nil, nil)
	defer mc.Close()

	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := closed.Addr().String()
	if err := closed.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	_, err = proxy.Dial(testCtx(t, 3*time.Second), mc, "tcp", addr)
	if err == nil {
		t.Fatal("Dial succeeded; want connection refused")
	}
	var pe *proxy.Error
	if !errors.As(err, &pe) {
		t.Fatalf("err type %T (%v)", err, err)
	}
	if pe.Status != proxy.StatusConnRefused {
		t.Fatalf("status=%v want ConnRefused (reason=%q)", pe.Status, pe.Reason)
	}
	srv.shutdown(t)
}

func TestProxyDialUnsupportedNetwork(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	srv, mc := startMiragePair(t, nil, nil)
	defer mc.Close()

	_, err := proxy.Dial(testCtx(t, time.Second), mc, "udp", "127.0.0.1:53")
	if err == nil {
		t.Fatal("Dial succeeded; want unsupported network")
	}
	srv.shutdown(t)
}

func TestProxyServerMetrics(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}

	echo := startTCPEchoServer(t)
	defer echo.Close()

	sink := metrics.NewMemorySink()
	srv, mc := startMiragePair(t, nil, sink)
	defer mc.Close()

	conn, err := proxy.Dial(testCtx(t, 3*time.Second), mc, "tcp", echo.Addr().String())
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	got := readN(t, conn, 4)
	if string(got) != "ping" {
		t.Fatalf("echo got %q", got)
	}
	_ = conn.Close()
	srv.shutdown(t)

	if got := sink.CounterValue("proxy.streams_accepted"); got == 0 {
		t.Fatalf("streams_accepted=0; want >=1")
	}
	if got := sink.CounterValue("proxy.dial_ok"); got == 0 {
		t.Fatalf("dial_ok=0; want >=1")
	}
}

// ---- shared harness ----

type harness struct {
	server *handshake.Server
	pconn  net.PacketConn
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func (h *harness) shutdown(t *testing.T) {
	t.Helper()
	h.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := h.server.Drain(ctx); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		t.Logf("Drain: %v", err)
	}
	_ = h.server.Close()
	_ = h.pconn.Close()
	h.wg.Wait()
}

func startMiragePair(t *testing.T, authz adapter.ProxyAuthorizer, sink metrics.Sink) (*harness, *client.Conn) {
	t.Helper()

	pconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	mk := make([]byte, 32)
	if _, err := rand.Read(mk); err != nil {
		t.Fatalf("rand: %v", err)
	}
	short := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	uid := adapter.UserID{0xAA}

	srv := &handshake.Server{
		PacketConn: pconn,
		TLSConfig:  selfSignedTLS(t, testSNI),
		MasterKey:  mk,
		Authenticator: adapter.UserAuthenticatorFunc(func(_ context.Context, _ []byte) (adapter.UserID, error) {
			return uid, nil
		}),
		QUICConfig: &quic.Config{HandshakeIdleTimeout: 5 * time.Second},
		Metrics:    sink,
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("server start: %v", err)
	}

	ps := &proxy.Server{Authorizer: authz, Metrics: sink}
	ctx, cancel := context.WithCancel(context.Background())

	h := &harness{server: srv, pconn: pconn, cancel: cancel}
	h.wg.Add(1)
	go func() {
		defer h.wg.Done()
		for {
			conn, err := srv.Accept(ctx)
			if err != nil {
				return
			}
			h.wg.Add(1)
			go func() {
				defer h.wg.Done()
				_ = ps.Serve(ctx, conn)
				_ = conn.CloseWithError(0, "")
			}()
		}
	}()

	var master [32]byte
	copy(master[:], mk)
	cli, err := client.Dial(testCtx(t, 5*time.Second), pconn.LocalAddr().String(), &client.Config{
		ServerName: testSNI,
		MasterKey:  master,
		ShortID:    short,
		ALPN:       []string{"h3"},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
		HandshakeTimeout: 5 * time.Second,
	})
	if err != nil {
		h.shutdown(t)
		t.Fatalf("client dial: %v", err)
	}
	return h, cli
}

func startTCPEchoServer(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return ln
}

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
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatalf("keypair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}
}

func readN(t *testing.T, r io.Reader, n int) []byte {
	t.Helper()
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		t.Fatalf("ReadFull: %v", err)
	}
	return buf
}

func testCtx(t *testing.T, d time.Duration) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}
