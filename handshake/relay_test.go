package handshake

import (
	"bytes"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// startEchoUDP starts a UDP echo server on a random port and returns its
// host, port, and a stop function. The server appends the byte 0xFF to
// every reply so tests can tell echo packets apart from forwarded ones.
func startEchoUDP(t *testing.T) (host string, port uint16, stop func()) {
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
			out = append(out, 0xFF)
			_, _ = pc.WriteToUDP(out, peer)
		}
	}()

	stop = func() {
		_ = pc.Close()
		<-done
	}
	return addr.IP.String(), uint16(addr.Port), stop
}

func TestRelayEchoesUpstreamReplies(t *testing.T) {
	upstreamHost, upstreamPort, stopUpstream := startEchoUDP(t)
	defer stopUpstream()

	// "Server" listening socket: relay writes downstream replies here.
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	defer server.Close()

	// "Client" socket: opens a flow to server, expects echo back.
	client, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen client: %v", err)
	}
	defer client.Close()

	r := &Relay{Downstream: server}
	defer r.Close()

	// Client sends to server; server pretends it received an unauthenticated
	// packet and hands it to the relay.
	payload := []byte("hello mirage")
	if _, err := client.WriteToUDP(payload, server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("client write: %v", err)
	}

	buf := make([]byte, 1500)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, clientAddr, err := server.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("server got %q, want %q", buf[:n], payload)
	}

	if err := r.Forward(clientAddr, upstreamHost, upstreamPort, buf[:n]); err != nil {
		t.Fatalf("Forward: %v", err)
	}

	// Echo plus 0xFF must arrive at the client.
	_ = client.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("client read: %v", err)
	}
	want := append([]byte{}, payload...)
	want = append(want, 0xFF)
	if !bytes.Equal(buf[:n], want) {
		t.Fatalf("client got %q, want %q", buf[:n], want)
	}
}

func TestRelayReusesSessionPerClient(t *testing.T) {
	upstreamHost, upstreamPort, stopUpstream := startEchoUDP(t)
	defer stopUpstream()

	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	defer server.Close()

	r := &Relay{Downstream: server}
	defer r.Close()

	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 65000}
	for i := 0; i < 5; i++ {
		if err := r.Forward(client, upstreamHost, upstreamPort, []byte{byte(i)}); err != nil {
			t.Fatalf("Forward %d: %v", i, err)
		}
	}

	r.mu.Lock()
	if got := len(r.sessions); got != 1 {
		r.mu.Unlock()
		t.Fatalf("session count = %d, want 1", got)
	}
	r.mu.Unlock()
}

func TestRelayReapsIdleSessions(t *testing.T) {
	upstreamHost, upstreamPort, stopUpstream := startEchoUDP(t)
	defer stopUpstream()

	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	defer server.Close()

	r := &Relay{Downstream: server, IdleTimeout: 100 * time.Millisecond}
	defer r.Close()

	client := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 65111}
	if err := r.Forward(client, upstreamHost, upstreamPort, []byte("x")); err != nil {
		t.Fatalf("Forward: %v", err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		r.mu.Lock()
		n := len(r.sessions)
		r.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("session was not reaped after idle timeout")
}

func TestRelayConcurrentClients(t *testing.T) {
	upstreamHost, upstreamPort, stopUpstream := startEchoUDP(t)
	defer stopUpstream()

	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	defer server.Close()

	r := &Relay{Downstream: server}
	defer r.Close()

	const clients = 16
	var wg sync.WaitGroup
	wg.Add(clients)
	for i := 0; i < clients; i++ {
		go func(id int) {
			defer wg.Done()
			addr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 50000 + id}
			if err := r.Forward(addr, upstreamHost, upstreamPort, []byte(strconv.Itoa(id))); err != nil {
				t.Errorf("forward %d: %v", id, err)
			}
		}(i)
	}
	wg.Wait()

	r.mu.Lock()
	got := len(r.sessions)
	r.mu.Unlock()
	if got != clients {
		t.Fatalf("session count = %d, want %d", got, clients)
	}
}

func TestRelayCloseIsIdempotent(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen server: %v", err)
	}
	defer server.Close()

	r := &Relay{Downstream: server}
	if err := r.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestRelayWithoutDownstreamErrors(t *testing.T) {
	r := &Relay{}
	err := r.Forward(&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1}, "127.0.0.1", 1, []byte("x"))
	if err == nil {
		t.Fatal("Forward without Downstream should error")
	}
}
