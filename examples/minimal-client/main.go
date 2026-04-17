// minimal-client dials a mirage server and runs a tiny SOCKS5 frontend
// on the loopback interface. Every SOCKS5 CONNECT is multiplexed onto a
// new mirage stream via the proxy package.
//
// Pair it with examples/minimal-server. After both are running, point
// curl or a browser at socks5://127.0.0.1:1080 (the default).
//
// This is example code: the InsecureSkipVerify flag, the static
// short-id, and the absence of reconnection logic are inappropriate
// for production use.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/valtrogen/mirage/client"
	"github.com/valtrogen/mirage/proxy"
)

var (
	addr        = flag.String("addr", "127.0.0.1:4433", "mirage server host:port")
	sni         = flag.String("sni", "www.example.com", "TLS server name")
	masterHex   = flag.String("master-key", "", "64-char hex master key (must match server)")
	shortHex    = flag.String("short-id", "1111111111111111", "16-char hex short-id")
	insecure    = flag.Bool("insecure-skip-verify", true, "skip server cert verification")
	socksListen = flag.String("socks", "127.0.0.1:1080", "local SOCKS5 listen address")
	dialTimeout = flag.Duration("timeout", 10*time.Second, "mirage handshake timeout")
)

func main() {
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	master := decodeFixed(logger, *masterHex, 32, "master-key")
	short := decodeFixed(logger, *shortHex, 8, "short-id")
	var (
		mk  [32]byte
		sid [8]byte
	)
	copy(mk[:], master)
	copy(sid[:], short)

	dialCtx, cancelDial := context.WithTimeout(context.Background(), *dialTimeout)
	mirageConn, err := client.Dial(dialCtx, *addr, &client.Config{
		ServerName:       *sni,
		MasterKey:        mk,
		ShortID:          sid,
		ALPN:             []string{"h3"},
		HandshakeTimeout: *dialTimeout,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: *insecure,
			NextProtos:         []string{"h3"},
		},
	})
	cancelDial()
	if err != nil {
		logger.Error("mirage dial", "err", err)
		os.Exit(1)
	}
	defer mirageConn.Close()
	logger.Info("connected to mirage server",
		"remote", mirageConn.RemoteAddr().String(),
		"local", mirageConn.LocalAddr().String())

	socksLn, err := net.Listen("tcp", *socksListen)
	if err != nil {
		logger.Error("socks listen", "err", err)
		os.Exit(1)
	}
	defer socksLn.Close()
	logger.Info("SOCKS5 listening", "addr", socksLn.Addr().String())

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go func() {
		<-ctx.Done()
		_ = socksLn.Close()
	}()

	var wg sync.WaitGroup
	for {
		c, err := socksLn.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			logger.Warn("socks accept", "err", err)
			continue
		}
		wg.Add(1)
		go func(c net.Conn) {
			defer wg.Done()
			defer c.Close()
			if err := handleSOCKS(ctx, mirageConn, c, logger); err != nil {
				logger.Debug("socks session", "err", err)
			}
		}(c)
	}
	wg.Wait()
}

// ---- SOCKS5 (RFC 1928, no auth + CONNECT only) ----

const (
	socksVersion = 0x05
	authNone     = 0x00
	cmdConnect   = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSucceeded            = 0x00
	repGeneralFail          = 0x01
	repNotAllowed           = 0x02
	repNetworkUnreachable   = 0x03
	repHostUnreachable      = 0x04
	repConnectionRefused    = 0x05
	repTTLExpired           = 0x06
	repCommandNotSupported  = 0x07
	repAddrTypeNotSupported = 0x08
)

func handleSOCKS(ctx context.Context, mc *client.Conn, c net.Conn, logger *slog.Logger) error {
	if err := c.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return err
	}

	if err := negotiate(c); err != nil {
		return fmt.Errorf("negotiate: %w", err)
	}

	target, err := readConnectRequest(c)
	if err != nil {
		_ = writeReply(c, repGeneralFail)
		return fmt.Errorf("read request: %w", err)
	}
	_ = c.SetDeadline(time.Time{})

	dialCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	upstream, err := proxy.Dial(dialCtx, mc, "tcp", target)
	cancel()
	if err != nil {
		var pe *proxy.Error
		if errors.As(err, &pe) {
			_ = writeReply(c, mapStatusToSOCKS(pe.Status))
		} else {
			_ = writeReply(c, repGeneralFail)
		}
		return fmt.Errorf("proxy.Dial %s: %w", target, err)
	}
	defer upstream.Close()

	if err := writeReply(c, repSucceeded); err != nil {
		return fmt.Errorf("write reply: %w", err)
	}

	logger.Debug("bridging", "target", target)
	bridge(c, upstream)
	return nil
}

func negotiate(c net.Conn) error {
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return err
	}
	if head[0] != socksVersion {
		return fmt.Errorf("bad socks version 0x%02x", head[0])
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return err
	}
	for _, m := range methods {
		if m == authNone {
			_, err := c.Write([]byte{socksVersion, authNone})
			return err
		}
	}
	_, _ = c.Write([]byte{socksVersion, 0xFF})
	return errors.New("no acceptable auth method")
}

func readConnectRequest(c net.Conn) (string, error) {
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", err
	}
	if head[0] != socksVersion {
		return "", fmt.Errorf("bad socks version 0x%02x", head[0])
	}
	if head[1] != cmdConnect {
		return "", fmt.Errorf("unsupported cmd 0x%02x", head[1])
	}

	var host string
	switch head[3] {
	case atypIPv4:
		var raw [net.IPv4len]byte
		if _, err := io.ReadFull(c, raw[:]); err != nil {
			return "", err
		}
		host = net.IP(raw[:]).String()
	case atypIPv6:
		var raw [net.IPv6len]byte
		if _, err := io.ReadFull(c, raw[:]); err != nil {
			return "", err
		}
		host = net.IP(raw[:]).String()
	case atypDomain:
		var lb [1]byte
		if _, err := io.ReadFull(c, lb[:]); err != nil {
			return "", err
		}
		buf := make([]byte, lb[0])
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		host = string(buf)
	default:
		return "", fmt.Errorf("unsupported atyp 0x%02x", head[3])
	}

	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:])))), nil
}

func writeReply(c net.Conn, rep byte) error {
	// BND.ADDR=0.0.0.0, BND.PORT=0; the SOCKS5 client doesn't need
	// the real bound address for CONNECT.
	resp := []byte{socksVersion, rep, 0x00, atypIPv4, 0, 0, 0, 0, 0, 0}
	_, err := c.Write(resp)
	return err
}

func mapStatusToSOCKS(s proxy.Status) byte {
	switch s {
	case proxy.StatusOK:
		return repSucceeded
	case proxy.StatusNotAllowed:
		return repNotAllowed
	case proxy.StatusHostUnreach:
		return repHostUnreachable
	case proxy.StatusNetworkUnreach:
		return repNetworkUnreachable
	case proxy.StatusConnRefused:
		return repConnectionRefused
	case proxy.StatusTTLExpired:
		return repTTLExpired
	case proxy.StatusBadRequest:
		return repCommandNotSupported
	default:
		return repGeneralFail
	}
}

func bridge(a net.Conn, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		if cw, ok := b.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = b.Close()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if cw, ok := a.(interface{ CloseWrite() error }); ok {
			_ = cw.CloseWrite()
		} else {
			_ = a.Close()
		}
	}()
	wg.Wait()
}

func decodeFixed(logger *slog.Logger, h string, want int, name string) []byte {
	raw, err := hex.DecodeString(h)
	if err != nil {
		logger.Error("not hex", "field", name)
		os.Exit(1)
	}
	if len(raw) != want {
		logger.Error("wrong length", "field", name, "want", want, "got", len(raw))
		os.Exit(1)
	}
	return raw
}
