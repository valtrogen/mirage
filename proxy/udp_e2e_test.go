package proxy_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/proxy"
)

// startUDPEchoServer binds an ephemeral UDP socket on loopback that
// echoes every datagram back to its sender. The returned address is
// the socket's local address; the cleanup func cancels and closes it.
func startUDPEchoServer(t *testing.T) (*net.UDPAddr, func()) {
	t.Helper()
	uconn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("udp echo listen: %v", err)
	}
	stop := make(chan struct{})
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, src, err := uconn.ReadFromUDP(buf)
			if err != nil {
				select {
				case <-stop:
					return
				default:
					return
				}
			}
			_, _ = uconn.WriteToUDP(append([]byte(nil), buf[:n]...), src)
		}
	}()
	return uconn.LocalAddr().(*net.UDPAddr), func() {
		close(stop)
		_ = uconn.Close()
	}
}

func TestProxyUDPAssociateEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	echoAddr, echoCleanup := startUDPEchoServer(t)
	defer echoCleanup()

	srv, mc := startMiragePair(t, nil, nil)
	defer mc.Close()

	pc, err := proxy.DialPacket(testCtx(t, 5*time.Second), mc)
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer pc.Close()

	const datagrams = 8
	want := make([][]byte, datagrams)
	for i := 0; i < datagrams; i++ {
		want[i] = []byte{byte(0xA0 + i), byte(i), 0xCC, 0xDD, byte(i)}
	}

	for _, p := range want {
		_ = pc.SetWriteDeadline(time.Now().Add(2 * time.Second))
		if _, err := pc.WriteTo(p, echoAddr); err != nil {
			t.Fatalf("WriteTo: %v", err)
		}
	}

	got := make([][]byte, 0, datagrams)
	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	for len(got) < datagrams {
		_ = pc.SetReadDeadline(deadline)
		n, src, err := pc.ReadFrom(buf)
		if err != nil {
			t.Fatalf("ReadFrom (have %d): %v", len(got), err)
		}
		if src.String() != echoAddr.String() {
			t.Fatalf("src=%v want %v", src, echoAddr)
		}
		got = append(got, append([]byte(nil), buf[:n]...))
	}

	for i, p := range want {
		if !bytes.Equal(got[i], p) {
			t.Fatalf("datagram %d mismatch: got=%x want=%x", i, got[i], p)
		}
	}
	srv.shutdown(t)
}

// TestProxyUDPAssociateAuthorizerDeniesPerPacket verifies that
// AuthorizeUDP gates each datagram individually and that denied
// packets are dropped silently rather than tearing the stream down.
func TestProxyUDPAssociateAuthorizerDeniesPerPacket(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test")
	}
	echoAddr, echoCleanup := startUDPEchoServer(t)
	defer echoCleanup()

	allowed := &atomic.Uint64{}
	allowed.Store(uint64(echoAddr.Port))

	authz := &portAuth{allowedPort: allowed}
	srv, mc := startMiragePair(t, authz, nil)
	defer mc.Close()

	pc, err := proxy.DialPacket(testCtx(t, 5*time.Second), mc)
	if err != nil {
		t.Fatalf("DialPacket: %v", err)
	}
	defer pc.Close()

	// Round 1: allowed destination — must echo back.
	if _, err := pc.WriteTo([]byte("ping"), echoAddr); err != nil {
		t.Fatalf("WriteTo allowed: %v", err)
	}
	buf := make([]byte, 64)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom allowed: %v", err)
	}
	if string(buf[:n]) != "ping" {
		t.Fatalf("got %q want ping", buf[:n])
	}

	// Round 2: denied destination — write succeeds (the policy check
	// runs server-side), but we should not get an echo back, because
	// the packet was dropped before sendto.
	wrong := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(echoAddr.Port) + 1}
	if _, err := pc.WriteTo([]byte("blocked"), wrong); err != nil {
		t.Fatalf("WriteTo blocked: %v", err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	if _, _, err := pc.ReadFrom(buf); err == nil {
		t.Fatalf("expected timeout after blocked send")
	}

	srv.shutdown(t)
}

// portAuth allows TCP unconditionally and UDP only for a single port.
type portAuth struct {
	allowedPort *atomic.Uint64
}

func (p *portAuth) AuthorizeTCP(context.Context, adapter.UserID, string, uint16) error {
	return nil
}

func (p *portAuth) AuthorizeUDP(_ context.Context, _ adapter.UserID, _ string, port uint16) error {
	if uint64(port) == p.allowedPort.Load() {
		return nil
	}
	return fmt.Errorf("port %d denied", port)
}

// silence unused-import warnings for build tag combinations.
var (
	_ = bytes.Equal
	_ = errors.Is
)
