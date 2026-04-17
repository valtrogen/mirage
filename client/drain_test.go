package client_test

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/client"
	"github.com/valtrogen/mirage/handshake"
	"github.com/valtrogen/mirage/metrics"
)

// TestServerDrainBlocksUntilConnExits exercises the full drain path:
// a real client dials, the server records a live connection, Drain is
// called with a deadline, and we verify the deadline elapses before
// the connection is closed. After the client closes, a second Drain
// call returns immediately.
func TestServerDrainBlocksUntilConnExits(t *testing.T) {
	if testing.Short() {
		t.Skip("integration drain")
	}

	pconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer pconn.Close()

	var masterKey [32]byte
	copy(masterKey[:], []byte("mirage-test-master-key-32-bytes!!"))
	shortID := [8]byte{2, 2, 2, 2, 2, 2, 2, 2}

	auth := adapter.UserAuthenticatorFunc(func(_ context.Context, _ []byte) (adapter.UserID, error) {
		return adapter.UserID{0x42}, nil
	})

	sink := metrics.NewMemorySink()
	srv := &handshake.Server{
		PacketConn:    pconn,
		TLSConfig:     selfSignedTLS(t, "drain.test"),
		MasterKey:     masterKey[:],
		Authenticator: auth,
		Metrics:       sink,
		QUICConfig:    &quic.Config{HandshakeIdleTimeout: 5 * time.Second},
	}
	if err := srv.Start(); err != nil {
		t.Fatalf("server start: %v", err)
	}
	defer srv.Close()

	accepted := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		c, err := srv.Accept(ctx)
		if err != nil {
			t.Errorf("Accept: %v", err)
			return
		}
		close(accepted)
		<-c.Context().Done()
	}()

	cli, err := client.Dial(context.Background(), pconn.LocalAddr().String(), &client.Config{
		ServerName: "drain.test",
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
		t.Fatalf("Dial: %v", err)
	}

	select {
	case <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("server never reported Accept")
	}

	if got := sink.GaugeValue("server.live_connections"); got != 1 {
		t.Fatalf("live_connections=%d want 1", got)
	}

	drainCtx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = srv.Drain(drainCtx)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Drain err=%v want DeadlineExceeded", err)
	}
	if elapsed < 200*time.Millisecond {
		t.Fatalf("Drain returned too quickly: %v", elapsed)
	}

	_ = cli.Close()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if sink.GaugeValue("server.live_connections") == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := sink.GaugeValue("server.live_connections"); got != 0 {
		t.Fatalf("live_connections=%d want 0 after client close", got)
	}

	drainCtx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := srv.Drain(drainCtx2); err != nil {
		t.Fatalf("second Drain: %v", err)
	}
}
