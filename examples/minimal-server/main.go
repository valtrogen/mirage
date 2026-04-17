// minimal-server starts a mirage server. With -config it loads a TOML
// file (see ../../config); without -config it falls back to a self-
// signed cert, a hard-coded SNI relay pool, and either a flag-supplied
// or randomly generated master key. The flag mode is intended for
// ad-hoc development; production deployments must use -config so that
// keys, TLS material, user table and SNI table all live on disk.
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/config"
	"github.com/valtrogen/mirage/handshake"
	"github.com/valtrogen/mirage/proxy"
)

var (
	configPath = flag.String("config", "", "path to TOML config (preferred); when set all -listen/-sni/-relay/-master-key/-drain flags are ignored")

	listen    = flag.String("listen", ":4433", "UDP listen address (ignored when -config is set)")
	sni       = flag.String("sni", "www.example.com", "TLS server name (ignored when -config is set)")
	upstream  = flag.String("relay", "1.1.1.1:443", "relay target host:port for unauthenticated traffic (ignored when -config is set)")
	masterHex = flag.String("master-key", "", "32-byte master key as hex (ignored when -config is set; random if empty)")
	drainWait = flag.Duration("drain", 10*time.Second, "max time to wait for in-flight conns on shutdown (ignored when -config is set)")
)

func main() {
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	rt, err := buildRuntime(logger)
	if err != nil {
		logger.Error("startup", "err", err)
		os.Exit(1)
	}
	defer rt.pc.Close()

	if err := rt.srv.Start(); err != nil {
		logger.Error("server start", "err", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	go acceptLoop(ctx, logger, rt.srv, rt.proxy)

	<-ctx.Done()
	logger.Info("shutdown requested; draining", "timeout", rt.drain)

	drainCtx, drainCancel := context.WithTimeout(context.Background(), rt.drain)
	defer drainCancel()
	if err := rt.srv.Drain(drainCtx); err != nil {
		logger.Warn("drain finished with error", "err", err)
	}
	if err := rt.srv.Close(); err != nil {
		logger.Warn("close", "err", err)
	}
}

// runtime bundles the live process objects so buildRuntime can return
// either flag-mode or config-mode results without branching downstream.
type runtime struct {
	pc    net.PacketConn
	srv   *handshake.Server
	proxy *proxy.Server
	drain time.Duration
}

func buildRuntime(logger *slog.Logger) (*runtime, error) {
	if *configPath != "" {
		return runtimeFromConfig(logger, *configPath)
	}
	return runtimeFromFlags(logger)
}

func runtimeFromConfig(logger *slog.Logger, path string) (*runtime, error) {
	m, err := config.LoadFile(path)
	if err != nil {
		return nil, err
	}
	if m.TLSConfig == nil {
		return nil, fmt.Errorf("config %s: tls_cert/tls_key are required", path)
	}
	if m.Authenticator == nil {
		return nil, fmt.Errorf("config %s: at least one [[user]] is required", path)
	}

	pc, err := net.ListenPacket("udp", m.Listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", m.Listen, err)
	}
	logger.Info("listening", "addr", pc.LocalAddr().String(), "source", "config")

	srv := &handshake.Server{
		PacketConn:           pc,
		TLSConfig:            m.TLSConfig,
		MasterKey:            m.MasterKey,
		AdditionalMasterKeys: m.AdditionalMasterKeys,
		Authenticator:        m.Authenticator,
		SNITargets:           m.SNITargets,
		SessionTTL:           m.SessionTTL,
		AuthQueueDepth:       m.AuthQueueDepth,
		InitialRatePerSec:    float64(m.RateLimitInitialPerSec),
		InitialRateBurst:     float64(m.RateLimitBurst),
		RecycleBounds:        m.RecycleBounds,
		Logger:               logger.With("component", "handshake"),
	}

	ps := &proxy.Server{
		Authorizer: adapter.AllowAllProxyAuthorizer{},
		Logger:     logger.With("component", "proxy"),
	}

	drain := m.Drain
	if drain == 0 {
		drain = 10 * time.Second
	}
	return &runtime{pc: pc, srv: srv, proxy: ps, drain: drain}, nil
}

func runtimeFromFlags(logger *slog.Logger) (*runtime, error) {
	pc, err := net.ListenPacket("udp", *listen)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", *listen, err)
	}
	logger.Info("listening", "addr", pc.LocalAddr().String(), "source", "flags")

	tlsConf := selfSigned(logger, *sni)

	host, port, err := splitHostPort(*upstream)
	if err != nil {
		pc.Close()
		return nil, fmt.Errorf("relay %s: %w", *upstream, err)
	}
	mk := loadOrGenerateKey(logger, *masterHex)

	srv := &handshake.Server{
		PacketConn: pc,
		TLSConfig:  tlsConf,
		MasterKey:  mk,
		Authenticator: adapter.UserAuthenticatorFunc(func(_ context.Context, shortID []byte) (adapter.UserID, error) {
			if len(shortID) != 8 {
				return adapter.UserID{}, adapter.ErrUnknownUser
			}
			return adapter.UserID{1}, nil
		}),
		SNITargets: &adapter.StaticSNITargetProvider{Targets: map[string]adapter.StaticTarget{
			*sni: {Host: host, Port: port},
		}},
		SessionTTL: 5 * time.Minute,
		Logger:     logger.With("component", "handshake"),
	}

	ps := &proxy.Server{
		Authorizer: adapter.AllowAllProxyAuthorizer{},
		Logger:     logger.With("component", "proxy"),
	}
	return &runtime{pc: pc, srv: srv, proxy: ps, drain: *drainWait}, nil
}

func acceptLoop(ctx context.Context, logger *slog.Logger, srv *handshake.Server, ps *proxy.Server) {
	for {
		conn, err := srv.Accept(ctx)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, net.ErrClosed) {
				return
			}
			logger.Warn("accept", "err", err)
			return
		}
		go func() {
			defer conn.CloseWithError(0, "")
			if err := ps.Serve(ctx, conn); err != nil && !errors.Is(err, context.Canceled) {
				logger.Debug("proxy.Serve returned", "err", err)
			}
		}()
	}
}

func loadOrGenerateKey(logger *slog.Logger, hexKey string) []byte {
	mk := make([]byte, 32)
	if hexKey != "" {
		raw, err := hex.DecodeString(hexKey)
		if err != nil || len(raw) != 32 {
			logger.Error("master-key must be 64 hex chars")
			os.Exit(1)
		}
		copy(mk, raw)
		return mk
	}
	if _, err := rand.Read(mk); err != nil {
		logger.Error("rand", "err", err)
		os.Exit(1)
	}
	logger.Info("generated random master key", "hex", hex.EncodeToString(mk))
	return mk
}

func selfSigned(logger *slog.Logger, name string) *tls.Config {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		logger.Error("genkey", "err", err)
		os.Exit(1)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{name},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		logger.Error("createcert", "err", err)
		os.Exit(1)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		logger.Error("marshalkey", "err", err)
		os.Exit(1)
	}
	cert, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		logger.Error("keypair", "err", err)
		os.Exit(1)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}}
}

func splitHostPort(s string) (string, uint16, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return "", 0, err
	}
	pa, err := net.LookupPort("udp", portStr)
	if err != nil {
		return "", 0, err
	}
	return host, uint16(pa), nil
}
