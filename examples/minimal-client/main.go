// minimal-client dials a mirage server, opens one bidirectional
// stream, writes stdin to it and prints the response on stdout. Pair
// it with examples/minimal-server for smoke tests.
package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"os"
	"time"

	"github.com/valtrogen/mirage/client"
)

var (
	addr      = flag.String("addr", "127.0.0.1:4433", "server host:port")
	sni       = flag.String("sni", "www.example.com", "TLS server name")
	masterHex = flag.String("master-key", "", "64-char hex master key (must match server)")
	shortHex  = flag.String("short-id", "1111111111111111", "16-char hex short-id")
	insecure  = flag.Bool("insecure-skip-verify", true, "skip server cert verification")
	timeout   = flag.Duration("timeout", 10*time.Second, "handshake timeout")
)

func main() {
	flag.Parse()

	mk := decodeFixed(*masterHex, 32, "master-key")
	sidRaw := decodeFixed(*shortHex, 8, "short-id")
	var master [32]byte
	var sid [8]byte
	copy(master[:], mk)
	copy(sid[:], sidRaw)

	cfg := &client.Config{
		ServerName:       *sni,
		MasterKey:        master,
		ShortID:          sid,
		ALPN:             []string{"h3"},
		HandshakeTimeout: *timeout,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: *insecure,
			NextProtos:         []string{"h3"},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	conn, err := client.Dial(ctx, *addr, cfg)
	if err != nil {
		log.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	log.Printf("connected to %s", conn.RemoteAddr())

	s, err := conn.OpenStream(context.Background())
	if err != nil {
		log.Fatalf("OpenStream: %v", err)
	}

	go func() {
		if _, err := io.Copy(os.Stdout, s); err != nil && err != io.EOF {
			log.Printf("recv: %v", err)
		}
	}()

	r := bufio.NewReader(os.Stdin)
	if _, err := io.Copy(s, r); err != nil {
		log.Fatalf("send: %v", err)
	}
	_ = s.Close()
	time.Sleep(200 * time.Millisecond)
}

func decodeFixed(h string, want int, name string) []byte {
	raw, err := hex.DecodeString(h)
	if err != nil {
		log.Fatalf("%s: not hex", name)
	}
	if len(raw) != want {
		log.Fatalf("%s: want %d bytes, got %d", name, want, len(raw))
	}
	return raw
}
