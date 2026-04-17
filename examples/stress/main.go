// stress opens -n connections to a mirage server, each carrying one
// bidirectional stream that echoes -size bytes. -c caps in-flight
// concurrency. Output is a single summary line plus dial/echo latency
// percentiles.
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/valtrogen/mirage/client"
)

var (
	addr      = flag.String("addr", "127.0.0.1:4433", "server host:port")
	sni       = flag.String("sni", "local.test", "TLS server name")
	masterHex = flag.String("master-key", "", "64-char hex master key")
	shortHex  = flag.String("short-id", "1111111111111111", "16-char hex short-id")
	total     = flag.Int("n", 100, "total connections")
	conc      = flag.Int("c", 16, "max concurrent in-flight connections")
	size      = flag.Int("size", 1024, "echo payload bytes per connection")
	hsTimeout = flag.Duration("hs-timeout", 5*time.Second, "handshake timeout per conn")
	rwTimeout = flag.Duration("rw-timeout", 10*time.Second, "read/write timeout per conn")
)

func main() {
	flag.Parse()

	master := decodeFixed(*masterHex, 32, "master-key")
	sid := decodeFixed(*shortHex, 8, "short-id")
	var mk [32]byte
	var sd [8]byte
	copy(mk[:], master)
	copy(sd[:], sid)

	payload := make([]byte, *size)
	if _, err := rand.Read(payload); err != nil {
		log.Fatalf("rand: %v", err)
	}

	cfg := &client.Config{
		ServerName:       *sni,
		MasterKey:        mk,
		ShortID:          sd,
		ALPN:             []string{"h3"},
		HandshakeTimeout: *hsTimeout,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			NextProtos:         []string{"h3"},
		},
	}

	results := make([]result, *total)
	var ok, fail uint64
	sem := make(chan struct{}, *conc)
	var wg sync.WaitGroup

	start := time.Now()
	for i := 0; i < *total; i++ {
		i := i
		sem <- struct{}{}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			results[i] = runOne(cfg, payload, *rwTimeout)
			if results[i].err != nil {
				atomic.AddUint64(&fail, 1)
			} else {
				atomic.AddUint64(&ok, 1)
			}
		}()
	}
	wg.Wait()
	elapsed := time.Since(start)

	report(results, ok, fail, elapsed, *conc, *size)
}

type result struct {
	dial time.Duration
	echo time.Duration
	err  error
}

func runOne(cfg *client.Config, payload []byte, rwTO time.Duration) (r result) {
	dialStart := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), cfg.HandshakeTimeout)
	defer cancel()
	conn, err := client.Dial(ctx, *addr, cfg)
	r.dial = time.Since(dialStart)
	if err != nil {
		r.err = fmt.Errorf("dial: %w", err)
		return
	}
	defer conn.Close()

	echoStart := time.Now()
	st, err := conn.OpenStream(context.Background())
	if err != nil {
		r.err = fmt.Errorf("open: %w", err)
		return
	}

	doneW := make(chan error, 1)
	go func() {
		_, werr := st.Write(payload)
		if werr != nil {
			doneW <- werr
			return
		}
		doneW <- st.Close()
	}()

	got := make([]byte, 0, len(payload))
	buf := make([]byte, 4096)
	deadline := time.Now().Add(rwTO)
	for len(got) < len(payload) {
		if time.Now().After(deadline) {
			r.err = fmt.Errorf("read timeout (have %d/%d)", len(got), len(payload))
			return
		}
		n, rerr := st.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if rerr != nil {
			if rerr == io.EOF {
				break
			}
			r.err = fmt.Errorf("read: %w", rerr)
			return
		}
	}
	if werr := <-doneW; werr != nil {
		r.err = fmt.Errorf("write: %w", werr)
		return
	}
	r.echo = time.Since(echoStart)
	if string(got) != string(payload) {
		r.err = fmt.Errorf("mismatch: got %d want %d", len(got), len(payload))
	}
	return
}

func report(rs []result, ok, fail uint64, total time.Duration, c, sz int) {
	dials := make([]time.Duration, 0, ok)
	echos := make([]time.Duration, 0, ok)
	errMap := map[string]int{}
	for _, r := range rs {
		if r.err != nil {
			errMap[r.err.Error()]++
			continue
		}
		dials = append(dials, r.dial)
		echos = append(echos, r.echo)
	}
	sort.Slice(dials, func(i, j int) bool { return dials[i] < dials[j] })
	sort.Slice(echos, func(i, j int) bool { return echos[i] < echos[j] })

	fmt.Fprintf(os.Stdout,
		"n=%d ok=%d fail=%d c=%d size=%d wall=%s rate=%.1f/s\n",
		len(rs), ok, fail, c, sz, total.Round(time.Millisecond),
		float64(len(rs))/total.Seconds(),
	)
	if len(echos) > 0 {
		fmt.Fprintf(os.Stdout,
			"dial p50=%s p95=%s p99=%s max=%s\n",
			pct(dials, 0.50), pct(dials, 0.95), pct(dials, 0.99), dials[len(dials)-1].Round(time.Millisecond),
		)
		fmt.Fprintf(os.Stdout,
			"echo p50=%s p95=%s p99=%s max=%s\n",
			pct(echos, 0.50), pct(echos, 0.95), pct(echos, 0.99), echos[len(echos)-1].Round(time.Millisecond),
		)
	}
	for msg, n := range errMap {
		fmt.Fprintf(os.Stdout, "err x%d: %s\n", n, msg)
	}
}

func pct(s []time.Duration, p float64) time.Duration {
	if len(s) == 0 {
		return 0
	}
	i := int(float64(len(s)-1) * p)
	return s[i].Round(time.Millisecond)
}

func decodeFixed(h string, want int, name string) []byte {
	raw, err := hex.DecodeString(h)
	if err != nil {
		log.Fatalf("%s: not hex", name)
	}
	if len(raw) != want {
		log.Fatalf("%s: want %d bytes got %d", name, want, len(raw))
	}
	return raw
}
