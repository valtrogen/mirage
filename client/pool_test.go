package client_test

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/valtrogen/mirage/client"
	"github.com/valtrogen/mirage/recycle"
)

// TestPoolDialsOnDemandAndCloses exercises the simplest Pool path:
// the first call to OpenStream forces a dial, subsequent calls reuse
// the same connection, and Close tears everything down cleanly.
func TestPoolDialsOnDemandAndCloses(t *testing.T) {
	if testing.Short() {
		t.Skip("pool dial integration")
	}
	addr, cleanup := startBBR2EchoServer(t)
	defer cleanup()

	var masterKey [32]byte
	copy(masterKey[:], []byte("mirage-test-master-key-32-bytes!!"))
	cfg := client.Config{
		ServerName: "bbr2.test",
		MasterKey:  masterKey,
		ShortID:    [8]byte{0xBB, 0x22, 0xE2, 0xE0, 0x42, 0x21, 0xF0, 0x01},
		ALPN:       []string{"h3"},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
		HandshakeTimeout: 6 * time.Second,
	}

	pool, err := client.NewPool(client.PoolConfig{
		Addr:        addr,
		Config:      cfg,
		DrainGrace:  100 * time.Millisecond,
		DialTimeout: 6 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	c1, err := pool.Active(context.Background())
	if err != nil {
		t.Fatalf("Active 1: %v", err)
	}
	c2, err := pool.Active(context.Background())
	if err != nil {
		t.Fatalf("Active 2: %v", err)
	}
	if c1 != c2 {
		t.Fatalf("Active should be sticky while connection is alive")
	}

	st, err := pool.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if _, err := st.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := st.Close(); err != nil {
		t.Fatalf("stream close: %v", err)
	}
	got := make([]byte, 0, 4)
	buf := make([]byte, 4)
	for len(got) < 4 {
		n, rerr := st.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			t.Fatalf("read: %v", rerr)
		}
	}
	if string(got) != "ping" {
		t.Fatalf("echo mismatch: %q", got)
	}
}

// TestPoolRecycleHintRotates simulates a server-emitted recycle hint
// by invoking the test seam Pool.TriggerRecycleHintForTest. After the
// hint fires the Pool must dial a fresh connection, return it from
// Active(), and close the old one once the grace window elapses.
func TestPoolRecycleHintRotates(t *testing.T) {
	if testing.Short() {
		t.Skip("pool recycle integration")
	}
	addr, cleanup := startBBR2EchoServer(t)
	defer cleanup()

	var masterKey [32]byte
	copy(masterKey[:], []byte("mirage-test-master-key-32-bytes!!"))
	cfg := client.Config{
		ServerName: "bbr2.test",
		MasterKey:  masterKey,
		ShortID:    [8]byte{0xBB, 0x22, 0xE2, 0xE0, 0x42, 0x21, 0xF0, 0x02},
		ALPN:       []string{"h3"},
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
		HandshakeTimeout: 6 * time.Second,
	}

	pool, err := client.NewPool(client.PoolConfig{
		Addr:        addr,
		Config:      cfg,
		DrainGrace:  150 * time.Millisecond,
		DialTimeout: 6 * time.Second,
	})
	if err != nil {
		t.Fatalf("NewPool: %v", err)
	}
	defer pool.Close()

	old, err := pool.Active(context.Background())
	if err != nil {
		t.Fatalf("Active: %v", err)
	}

	// Hand the pool a synthetic recycle hint as if the server had
	// emitted one on the control stream.
	pool.TriggerRecycleHintForTest(old, recycle.Hint{HandoffWindow: 80 * time.Millisecond})

	// Spin until the active conn changes (the rotation runs on a
	// background goroutine after dialing the replacement).
	deadline := time.Now().Add(5 * time.Second)
	var fresh *client.Conn
	for time.Now().Before(deadline) {
		c, err := pool.Active(context.Background())
		if err != nil {
			t.Fatalf("Active during rotate: %v", err)
		}
		if c != old {
			fresh = c
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if fresh == nil {
		t.Fatalf("pool did not rotate within deadline")
	}

	// Old conn must remain usable during the grace window — opening
	// a stream on it directly should still succeed.
	st, err := old.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("old.OpenStream during grace: %v", err)
	}
	_ = st.Close()

	// After the grace window expires the pool must close the old
	// conn. We only require it to be closed within a few hundred ms;
	// the goroutine waits for the timer and then calls Close().
	closeDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(closeDeadline) {
		_, err := old.OpenStream(context.Background())
		if err != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if _, err := old.OpenStream(context.Background()); err == nil {
		t.Fatalf("old conn should be closed after grace window")
	}
}

