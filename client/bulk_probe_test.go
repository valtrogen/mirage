package client_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"sync/atomic"
	"testing"
	"time"
)

// TestBulkProbeBytes exercises a single-stream echo of increasing
// payload sizes against the loopback test server. With BBRv2,
// RFC 9002 loss recovery, RFC 9000 flow control, and RFC 9001 §6
// 1-RTT key updates wired in, payloads up to 1 MiB now complete on
// loopback. Anything larger is gated on the proxy adapter limits
// (server-side echo buffering) rather than the mirage data plane,
// so this test caps at 1 MiB.
//
// The test is skipped under -short because it spins up a fresh
// server per size and the wall-clock cost grows with the payload.
func TestBulkProbeBytes(t *testing.T) {
	if testing.Short() {
		t.Skip("bulk probe is long-form")
	}


	sizes := []int{
		64 * 1024,
		128 * 1024,
		256 * 1024,
		512 * 1024,
		1024 * 1024,
	}
	for _, sz := range sizes {
		sz := sz
		t.Run(byteName(sz), func(t *testing.T) {
			t.Helper()
			addr, cleanup := startBBR2EchoServer(t)
			defer cleanup()

			cli := dialBBR2(t, addr)
			defer func() { _ = cli.Close() }()

			st, err := cli.OpenStream(context.Background())
			if err != nil {
				t.Fatalf("OpenStream: %v", err)
			}
			payload := make([]byte, sz)
			if _, err := rand.Read(payload); err != nil {
				t.Fatalf("rand: %v", err)
			}

			var werr atomic.Value
			go func() {
				if _, err := st.Write(payload); err != nil {
					werr.Store(err)
					return
				}
				if err := st.Close(); err != nil {
					werr.Store(err)
				}
			}()

			got := make([]byte, 0, sz)
			buf := make([]byte, 64*1024)
			deadline := time.Now().Add(60 * time.Second)
			for len(got) < sz {
				if time.Now().After(deadline) {
					t.Fatalf("read timeout: have %d/%d bytes, in-flight=%d cwnd=%d",
						len(got), sz, cli.BytesInFlight(),
						cli.CongestionController().GetCongestionWindow())
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
			if v := werr.Load(); v != nil {
				t.Fatalf("write: %v", v.(error))
			}
			if len(got) != sz {
				t.Fatalf("got %d bytes want %d", len(got), sz)
			}
			t.Logf("ok %d bytes; cwnd=%d srtt=%v",
				sz, cli.CongestionController().GetCongestionWindow(),
				cli.RTT().SmoothedRTT())
		})
	}
}

func byteName(n int) string {
	switch {
	case n >= 1<<20:
		return formatN(n>>20) + "MiB"
	case n >= 1<<10:
		return formatN(n>>10) + "KiB"
	default:
		return formatN(n) + "B"
	}
}

func formatN(n int) string {
	const dec = "0123456789"
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = dec[n%10]
		n /= 10
	}
	return string(buf[i:])
}
