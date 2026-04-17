package client_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
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

// TestClientEchoStream runs end-to-end: dial, open a single bidi
// stream, write a few small payloads, expect each one back, then close.
// This exercises the full 1-RTT data plane in the client (ACK, send,
// recv, retransmit timer, FIN).
func TestClientEchoStream(t *testing.T) {
	if testing.Short() {
		t.Skip("integration echo")
	}

	pconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pconn.Close()

	var masterKey [32]byte
	copy(masterKey[:], []byte("mirage-test-master-key-32-bytes!!"))
	shortID := [8]byte{9, 9, 9, 9, 9, 9, 9, 9}
	wantUID := adapter.UserID{0xEE}

	auth := adapter.UserAuthenticatorFunc(func(_ context.Context, sid []byte) (adapter.UserID, error) {
		return wantUID, nil
	})

	srv := &handshake.Server{
		PacketConn:    pconn,
		TLSConfig:     selfSignedTLS(t, "echo.test"),
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
		st, err := c.AcceptStream(ctx)
		if err != nil {
			serverErr.Store(err)
			return
		}
		all, err := io.ReadAll(st)
		if err != nil {
			serverErr.Store(err)
			return
		}
		if _, err := st.Write(all); err != nil {
			serverErr.Store(err)
			return
		}
		if err := st.Close(); err != nil {
			serverErr.Store(err)
			return
		}
		<-c.Context().Done()
	}()

	cli, err := client.Dial(context.Background(), pconn.LocalAddr().String(), &client.Config{
		ServerName: "echo.test",
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
	defer func() { _ = cli.Close() }()

	st, err := cli.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}

	payloads := [][]byte{
		[]byte("hello mirage"),
		[]byte("second packet body"),
		[]byte("third"),
	}
	for _, p := range payloads {
		if _, err := st.Write(p); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	var got []byte
	deadline := time.Now().Add(5 * time.Second)
	buf := make([]byte, 1024)
	expected := 0
	for _, p := range payloads {
		expected += len(p)
	}
	for len(got) < expected {
		if time.Now().After(deadline) {
			t.Fatalf("read timeout: have %d/%d bytes", len(got), expected)
		}
		n, err := st.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			t.Fatalf("Read: %v", err)
		}
	}

	want := []byte{}
	for _, p := range payloads {
		want = append(want, p...)
	}
	if string(got) != string(want) {
		t.Fatalf("echo mismatch:\n got=%q\nwant=%q", got, want)
	}

	if err := cli.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()
	if v := serverErr.Load(); v != nil {
		t.Fatalf("server side: %v", v.(error))
	}
}
