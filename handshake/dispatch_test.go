package handshake

import (
	"bytes"
	"context"
	"crypto/rand"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/proto"
	"github.com/valtrogen/mirage/replay"
	"github.com/valtrogen/mirage/transport"
)

// echoUDPServer mirrors the helper in relay_test.go but appends 0xEE so
// the two test files do not collide if go test reorders things.
func startEchoUDPDisp(t *testing.T) (host string, port uint16, stop func()) {
	t.Helper()
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	addr := pc.LocalAddr().(*net.UDPAddr)
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 1500)
		for {
			n, peer, err := pc.ReadFromUDP(buf)
			if err != nil {
				close(done)
				return
			}
			out := append([]byte{}, buf[:n]...)
			out = append(out, 0xEE)
			_, _ = pc.WriteToUDP(out, peer)
		}
	}()
	stop = func() { _ = pc.Close(); <-done }
	return addr.IP.String(), uint16(addr.Port), stop
}

type fixedAuthenticator struct{ shortID []byte }

func (f *fixedAuthenticator) Verify(_ context.Context, sid []byte) (adapter.UserID, error) {
	if !bytes.Equal(sid, f.shortID) {
		return adapter.UserID{}, adapter.ErrUnknownUser
	}
	return adapter.UserID{1, 2, 3}, nil
}

func newDispatcherForTest(t *testing.T, mk []byte) (*Dispatcher, *net.UDPConn) {
	t.Helper()
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	k, err := NewKeyring(mk)
	if err != nil {
		t.Fatalf("keyring: %v", err)
	}
	d := &Dispatcher{
		PacketConn:    server,
		Keyring:       k,
		Authenticator: &fixedAuthenticator{shortID: []byte("87654321")},
		SessionTTL:    200 * time.Millisecond,
	}
	return d, server
}

func buildAuthInitial(t *testing.T, k *Keyring, shortID []byte, dcid []byte, pn uint32) []byte {
	t.Helper()
	wkey, err := replay.DeriveWindowKey(k.masterKey, replay.WindowID(time.Now()))
	if err != nil {
		t.Fatalf("derive: %v", err)
	}
	sid := make([]byte, proto.SessionIDLen)
	if err := EncodeSessionID(sid, wkey, shortID, replay.WindowID(time.Now())); err != nil {
		t.Fatalf("encode: %v", err)
	}
	hs := transport.BuildClientHelloHandshake(sid)
	cf := transport.BuildCRYPTOFrame(hs)
	pkt, err := transport.BuildInitial(dcid, nil, pn, cf, 1200)
	if err != nil {
		t.Fatalf("build initial: %v", err)
	}
	return pkt
}

func TestDispatcherAuthDelivery(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)

	d, server := newDispatcherForTest(t, mk)
	defer server.Close()
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer d.Close()

	dcid := bytes.Repeat([]byte{0xC1}, 8)
	pkt := buildAuthInitial(t, d.Keyring, []byte("87654321"), dcid, 1)

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()
	if _, err := client.WriteToUDP(pkt, server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	select {
	case dg := <-d.AuthChannel():
		if !bytes.Equal(dg.Data, pkt) {
			t.Fatalf("auth datagram bytes differ")
		}
		if (dg.UserID == adapter.UserID{}) {
			t.Fatal("UserID is zero on authenticated datagram")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no authenticated datagram delivered")
	}
}

func TestDispatcherRelayDelivery(t *testing.T) {
	upstreamHost, upstreamPort, stop := startEchoUDPDisp(t)
	defer stop()

	mk := make([]byte, 32)
	rand.Read(mk)
	d, server := newDispatcherForTest(t, mk)
	defer server.Close()
	d.SNITargets = &adapter.StaticSNITargetProvider{Targets: map[string]adapter.StaticTarget{
		"www.example.com": {Host: upstreamHost, Port: upstreamPort},
	}}
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer d.Close()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()

	probe := []byte("not a quic initial packet at all")
	if _, err := client.WriteToUDP(probe, server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 1500)
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	want := append([]byte{}, probe...)
	want = append(want, 0xEE)
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("relay reply mismatch: got %x want %x", buf[:n], want)
	}
}

func TestDispatcherDropsWhenNoSNITargets(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	d, server := newDispatcherForTest(t, mk)
	defer server.Close()
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer d.Close()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()

	if _, err := client.WriteToUDP([]byte("garbage"), server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case dg := <-d.AuthChannel():
		t.Fatalf("unexpected auth delivery: %x", dg.Data[:min(8, len(dg.Data))])
	case <-time.After(150 * time.Millisecond):
	}

	if d.SessionCount() != 1 {
		t.Fatalf("session count = %d, want 1 (drop entry cached)", d.SessionCount())
	}
}

func TestDispatcherCachesPerClientDecision(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	d, server := newDispatcherForTest(t, mk)
	defer server.Close()
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer d.Close()

	dcid := bytes.Repeat([]byte{0xC2}, 8)
	pkt := buildAuthInitial(t, d.Keyring, []byte("87654321"), dcid, 1)

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()

	for i := 0; i < 3; i++ {
		if _, err := client.WriteToUDP(pkt, server.LocalAddr().(*net.UDPAddr)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	timeout := time.After(2 * time.Second)
	for i := 0; i < 3; i++ {
		select {
		case <-d.AuthChannel():
		case <-timeout:
			t.Fatalf("only %d/3 datagrams delivered", i)
		}
	}
	if d.SessionCount() != 1 {
		t.Fatalf("session count = %d, want 1", d.SessionCount())
	}
}

func TestDispatcherReapsIdleSessions(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	d, server := newDispatcherForTest(t, mk)
	defer server.Close()
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer d.Close()

	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("client: %v", err)
	}
	defer client.Close()

	if _, err := client.WriteToUDP([]byte("x"), server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("write: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if d.SessionCount() == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("session was not reaped after TTL")
}

func TestDispatcherRequiresFields(t *testing.T) {
	if err := (&Dispatcher{}).Start(); err == nil {
		t.Fatal("Start with no PacketConn: want error")
	}
	pc, _ := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	defer pc.Close()
	if err := (&Dispatcher{PacketConn: pc}).Start(); err == nil {
		t.Fatal("Start with no Keyring: want error")
	}
	mk := make([]byte, 32)
	rand.Read(mk)
	k, _ := NewKeyring(mk)
	if err := (&Dispatcher{PacketConn: pc, Keyring: k}).Start(); err == nil {
		t.Fatal("Start with no Authenticator: want error")
	}
}

func TestDispatcherConcurrentClients(t *testing.T) {
	mk := make([]byte, 32)
	rand.Read(mk)
	d, server := newDispatcherForTest(t, mk)
	defer server.Close()
	if err := d.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer d.Close()

	const clients = 8
	var wg sync.WaitGroup
	wg.Add(clients)
	for i := 0; i < clients; i++ {
		go func(id int) {
			defer wg.Done()
			dcid := bytes.Repeat([]byte{byte(0x80 + id)}, 8)
			pkt := buildAuthInitial(t, d.Keyring, []byte("87654321"), dcid, uint32(id+1))
			client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Errorf("listen: %v", err)
				return
			}
			defer client.Close()
			if _, err := client.WriteToUDP(pkt, server.LocalAddr().(*net.UDPAddr)); err != nil {
				t.Errorf("write: %v", err)
			}
		}(i)
	}
	wg.Wait()

	got := 0
	timeout := time.After(2 * time.Second)
loop:
	for got < clients {
		select {
		case <-d.AuthChannel():
			got++
		case <-timeout:
			break loop
		}
	}
	if got != clients {
		t.Fatalf("delivered %d/%d", got, clients)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
