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

// TestEchoStreamPopulatesRTTAndDrainsInFlight runs a small echo
// roundtrip and verifies that:
//   - the RTT estimator records a sample (smoothed > 0, min > 0)
//   - all bytes-in-flight are drained after acks settle
//   - the BBRv2 controller is wired in (non-zero cwnd, CanSend
//     permits further sends after the small payload settles)
func TestEchoStreamPopulatesRTTAndDrainsInFlight(t *testing.T) {
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
	shortID := [8]byte{7, 7, 7, 7, 7, 7, 7, 7}
	wantUID := adapter.UserID{0xCC}

	auth := adapter.UserAuthenticatorFunc(func(_ context.Context, _ []byte) (adapter.UserID, error) {
		return wantUID, nil
	})

	srv := &handshake.Server{
		PacketConn:    pconn,
		TLSConfig:     selfSignedTLS(t, "wire.test"),
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
		_ = st.Close()
		<-c.Context().Done()
	}()

	cli, err := client.Dial(context.Background(), pconn.LocalAddr().String(), &client.Config{
		ServerName: "wire.test",
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

	if cli.CongestionController() == nil {
		t.Fatal("CongestionController must not be nil")
	}
	if cli.RTT() == nil {
		t.Fatal("RTT must not be nil")
	}

	st, err := cli.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	payload := []byte("congestion-wiring-payload")
	if _, err := st.Write(payload); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	got := make([]byte, 0, len(payload))
	buf := make([]byte, 1024)
	deadline := time.Now().Add(5 * time.Second)
	for len(got) < len(payload) {
		if time.Now().After(deadline) {
			t.Fatalf("read timeout: have %d/%d bytes", len(got), len(payload))
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
	if string(got) != string(payload) {
		t.Fatalf("echo mismatch: got=%q want=%q", got, payload)
	}

	rtt := cli.RTT()
	// The server (quic-go) may batch the ACK behind its
	// max_ack_delay window after writing the echo data, so the test
	// can race ahead of the ACK on loopback. Poll until either an
	// RTT sample lands or we exceed quic-go's worst-case delayed-ack
	// budget.
	rttDeadline := time.Now().Add(3 * time.Second)
	for !rtt.HasMeasurement() && time.Now().Before(rttDeadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !rtt.HasMeasurement() {
		t.Fatal("RTT.HasMeasurement should be true after a roundtrip")
	}
	if rtt.SmoothedRTT() <= 0 || rtt.MinRTT() <= 0 {
		t.Fatalf("RTT smoothed=%v min=%v, both should be > 0",
			rtt.SmoothedRTT(), rtt.MinRTT())
	}

	// Wait for any straggler acks; in-flight should drain to zero.
	settle := time.Now().Add(2 * time.Second)
	for time.Now().Before(settle) {
		if cli.BytesInFlight() == 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if got := cli.BytesInFlight(); got != 0 {
		t.Fatalf("BytesInFlight after settle = %d, want 0", got)
	}

	// BBRv2 controller must permit further sends from a fresh in-flight
	// (zero) and report a finite, non-zero cwnd.
	cc := cli.CongestionController()
	if !cc.CanSend(0) {
		t.Fatal("CanSend(0) should be true after settle")
	}
	if cwnd := cc.GetCongestionWindow(); cwnd == 0 {
		t.Fatal("BBRv2 cwnd should be > 0 after a roundtrip")
	}

	if err := cli.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	wg.Wait()
	if v := serverErr.Load(); v != nil {
		t.Fatalf("server side: %v", v.(error))
	}
}
