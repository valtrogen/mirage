// Package config provides a TOML schema for mirage server deployments
// and the loader that materialises it into a ready-to-Start
// handshake.Server / proxy.Server pair.
//
// The schema is intentionally narrow: it only covers parameters that
// operators *must* be able to change without recompiling. Anything
// else (Authenticator implementation, custom Authorizer, custom
// PadderPolicy) is wired by the calling binary because it is code
// rather than data.
//
// Example minimal deployment:
//
//	listen     = "0.0.0.0:443"
//	master_key = "00112233...64hex..."
//	tls_cert   = "/etc/mirage/cert.pem"
//	tls_key    = "/etc/mirage/key.pem"
//
//	[[user]]
//	short_id = "1111111111111111"
//	uid_hex  = "01"
//
//	[[sni_target]]
//	name = "www.example.com"
//	host = "1.1.1.1"
//	port = 443
//
//	[recycle]
//	age_min   = "90m"
//	age_max   = "180m"
//	bytes_min = 3221225472
//	bytes_max = 8589934592
package config

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/recycle"
)

// File is the on-disk TOML schema. Field names use snake_case so the
// rendered configuration reads naturally; the public Go fields keep
// CamelCase per Go convention.
type File struct {
	// Listen is the UDP listen address (host:port). Required.
	Listen string `toml:"listen"`

	// MasterKey is the active 32-byte master key in hex (64 chars).
	// Either MasterKey or MasterKeyFile must be set.
	MasterKey     string `toml:"master_key"`
	MasterKeyFile string `toml:"master_key_file"`

	// AdditionalMasterKeys is the make-before-break key set: previous
	// keys still allowed for verifying inbound session_ids during a
	// rotation window. Each entry is hex of length 64.
	AdditionalMasterKeys []string `toml:"additional_master_keys"`

	// TLSCert and TLSKey are PEM file paths. Required for production.
	TLSCert string `toml:"tls_cert"`
	TLSKey  string `toml:"tls_key"`

	// SessionTTL bounds how long the dispatcher keeps a 4-tuple
	// remembered after the last datagram. Strings parse via
	// time.ParseDuration.
	SessionTTL string `toml:"session_ttl"`

	// AuthQueueDepth caps the number of authenticated datagrams
	// buffered between dispatcher and accept loop. Zero means use
	// handshake.DefaultAuthQueueDepth.
	AuthQueueDepth int `toml:"auth_queue_depth"`

	// RateLimit configures the per-source-IP token bucket gating
	// unauthenticated traffic. All fields optional.
	RateLimit struct {
		InitialPerSec int    `toml:"initial_per_sec"`
		Burst         int    `toml:"burst"`
		Window        string `toml:"window"`
	} `toml:"rate_limit"`

	// Recycle configures the recycle.Bounds the server samples a
	// per-connection threshold from. Empty fields fall back to
	// recycle.DefaultBounds().
	Recycle struct {
		AgeMin   string `toml:"age_min"`
		AgeMax   string `toml:"age_max"`
		BytesMin uint64 `toml:"bytes_min"`
		BytesMax uint64 `toml:"bytes_max"`
	} `toml:"recycle"`

	// Users is the static authenticator's user table. Each entry
	// maps an 8-byte short_id (hex) to a 16-byte UID.
	Users []UserEntry `toml:"user"`

	// SNITargets is the relay-target table consulted for
	// unauthenticated traffic. Each entry maps an SNI to a forward
	// destination.
	SNITargets []SNIEntry `toml:"sni_target"`

	// Drain bounds how long the binary waits on shutdown for in-
	// flight connections to finish.
	Drain string `toml:"drain"`
}

// UserEntry is one row in the static user table.
type UserEntry struct {
	ShortID string `toml:"short_id"`
	UIDHex  string `toml:"uid_hex"`
}

// SNIEntry is one row in the static SNI relay table.
type SNIEntry struct {
	Name string `toml:"name"`
	Host string `toml:"host"`
	Port uint16 `toml:"port"`
}

// Materialised is the loader's output: the concrete artefacts a
// binary needs to construct a handshake.Server. The intermediate
// representation (File) is preserved so callers can inspect the
// original config too.
type Materialised struct {
	File File

	Listen               string
	MasterKey            []byte
	AdditionalMasterKeys [][]byte
	TLSConfig            *tls.Config
	SessionTTL           time.Duration
	AuthQueueDepth       int
	Drain                time.Duration

	RateLimitInitialPerSec int
	RateLimitBurst         int
	RateLimitWindow        time.Duration

	RecycleBounds recycle.Bounds

	Authenticator adapter.UserAuthenticator
	SNITargets    *adapter.StaticSNITargetProvider
}

// LoadFile reads the TOML file at path and returns a Materialised
// configuration. The loader validates required fields, parses
// durations, and constructs the static authenticator and SNI provider.
func LoadFile(path string) (*Materialised, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("config: open %s: %w", path, err)
	}
	defer f.Close()
	return load(f, path)
}

// LoadReader is the in-memory variant of LoadFile, useful for tests
// and dynamic configuration sources. label is included verbatim in
// any error messages so the operator can identify the source.
func LoadReader(r io.Reader, label string) (*Materialised, error) {
	return load(r, label)
}

func load(r io.Reader, label string) (*Materialised, error) {
	var raw File
	if _, err := toml.NewDecoder(r).Decode(&raw); err != nil {
		return nil, fmt.Errorf("config %s: parse: %w", label, err)
	}
	return Materialise(raw, label)
}

// Materialise converts a parsed File into runtime objects. Exported
// so tests and embedders can build a File programmatically.
func Materialise(raw File, label string) (*Materialised, error) {
	out := &Materialised{File: raw}

	if raw.Listen == "" {
		return nil, fmt.Errorf("config %s: listen is required", label)
	}
	out.Listen = raw.Listen

	mk, err := loadKeyMaterial(raw.MasterKey, raw.MasterKeyFile, "master_key", label)
	if err != nil {
		return nil, err
	}
	out.MasterKey = mk

	for i, hex := range raw.AdditionalMasterKeys {
		k, err := decodeHex(hex, "additional_master_keys[%d]", i)
		if err != nil {
			return nil, fmt.Errorf("config %s: %w", label, err)
		}
		if len(k) != 32 {
			return nil, fmt.Errorf("config %s: additional_master_keys[%d] must be 32 bytes, got %d", label, i, len(k))
		}
		out.AdditionalMasterKeys = append(out.AdditionalMasterKeys, k)
	}

	if raw.TLSCert != "" || raw.TLSKey != "" {
		if raw.TLSCert == "" || raw.TLSKey == "" {
			return nil, fmt.Errorf("config %s: tls_cert and tls_key must both be set", label)
		}
		cert, err := tls.LoadX509KeyPair(raw.TLSCert, raw.TLSKey)
		if err != nil {
			return nil, fmt.Errorf("config %s: load TLS keypair: %w", label, err)
		}
		out.TLSConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			NextProtos:   []string{"h3"},
		}
	}

	if out.SessionTTL, err = parseDuration(raw.SessionTTL, "session_ttl", label); err != nil {
		return nil, err
	}
	if out.Drain, err = parseDuration(raw.Drain, "drain", label); err != nil {
		return nil, err
	}
	winDur, err := parseDuration(raw.RateLimit.Window, "rate_limit.window", label)
	if err != nil {
		return nil, err
	}
	out.RateLimitWindow = winDur
	out.RateLimitInitialPerSec = raw.RateLimit.InitialPerSec
	out.RateLimitBurst = raw.RateLimit.Burst
	out.AuthQueueDepth = raw.AuthQueueDepth

	out.RecycleBounds = recycle.DefaultBounds()
	if raw.Recycle.AgeMin != "" {
		d, err := parseDuration(raw.Recycle.AgeMin, "recycle.age_min", label)
		if err != nil {
			return nil, err
		}
		out.RecycleBounds.AgeMin = d
	}
	if raw.Recycle.AgeMax != "" {
		d, err := parseDuration(raw.Recycle.AgeMax, "recycle.age_max", label)
		if err != nil {
			return nil, err
		}
		out.RecycleBounds.AgeMax = d
	}
	if raw.Recycle.BytesMin != 0 {
		out.RecycleBounds.BytesMin = raw.Recycle.BytesMin
	}
	if raw.Recycle.BytesMax != 0 {
		out.RecycleBounds.BytesMax = raw.Recycle.BytesMax
	}
	if out.RecycleBounds.AgeMin > out.RecycleBounds.AgeMax {
		return nil, fmt.Errorf("config %s: recycle.age_min > age_max", label)
	}
	if out.RecycleBounds.BytesMin > out.RecycleBounds.BytesMax {
		return nil, fmt.Errorf("config %s: recycle.bytes_min > bytes_max", label)
	}

	users, err := buildUserTable(raw.Users, label)
	if err != nil {
		return nil, err
	}
	out.Authenticator = users

	if len(raw.SNITargets) > 0 {
		out.SNITargets = &adapter.StaticSNITargetProvider{Targets: map[string]adapter.StaticTarget{}}
		for i, t := range raw.SNITargets {
			if t.Name == "" || t.Host == "" || t.Port == 0 {
				return nil, fmt.Errorf("config %s: sni_target[%d] requires name, host, port", label, i)
			}
			out.SNITargets.Targets[t.Name] = adapter.StaticTarget{Host: t.Host, Port: t.Port}
		}
	}

	return out, nil
}

func loadKeyMaterial(literal, filePath, field, label string) ([]byte, error) {
	switch {
	case literal != "" && filePath != "":
		return nil, fmt.Errorf("config %s: %s and %s_file are mutually exclusive", label, field, field)
	case literal != "":
		k, err := hex.DecodeString(strings.TrimSpace(literal))
		if err != nil {
			return nil, fmt.Errorf("config %s: %s: %w", label, field, err)
		}
		if len(k) != 32 {
			return nil, fmt.Errorf("config %s: %s must be 32 bytes (64 hex chars), got %d", label, field, len(k))
		}
		return k, nil
	case filePath != "":
		raw, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("config %s: read %s_file: %w", label, field, err)
		}
		k, err := hex.DecodeString(strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, fmt.Errorf("config %s: %s_file content: %w", label, field, err)
		}
		if len(k) != 32 {
			return nil, fmt.Errorf("config %s: %s_file must hold 32 bytes (64 hex chars)", label, field)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("config %s: %s or %s_file is required", label, field, field)
	}
}

func decodeHex(s, format string, args ...interface{}) ([]byte, error) {
	out, err := hex.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return nil, fmt.Errorf(format+": %w", append(args, err)...)
	}
	return out, nil
}

func parseDuration(s, field, label string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("config %s: %s: %w", label, field, err)
	}
	return d, nil
}

// staticUserTable is the in-memory representation of the [[user]]
// section: an 8-byte short_id keyed lookup that returns the UserID
// the operator assigned to that short_id.
type staticUserTable map[[8]byte]adapter.UserID

func buildUserTable(entries []UserEntry, label string) (adapter.UserAuthenticator, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	t := make(staticUserTable, len(entries))
	for i, e := range entries {
		shortID, err := hex.DecodeString(strings.TrimSpace(e.ShortID))
		if err != nil {
			return nil, fmt.Errorf("config %s: user[%d].short_id: %w", label, i, err)
		}
		if len(shortID) != 8 {
			return nil, fmt.Errorf("config %s: user[%d].short_id must be 8 bytes, got %d", label, i, len(shortID))
		}
		uidRaw, err := hex.DecodeString(strings.TrimSpace(e.UIDHex))
		if err != nil {
			return nil, fmt.Errorf("config %s: user[%d].uid_hex: %w", label, i, err)
		}
		if len(uidRaw) == 0 || len(uidRaw) > 16 {
			return nil, fmt.Errorf("config %s: user[%d].uid_hex must be 1-16 bytes", label, i)
		}
		var key [8]byte
		copy(key[:], shortID)
		var uid adapter.UserID
		copy(uid[:], uidRaw)
		t[key] = uid
	}
	return adapter.UserAuthenticatorFunc(func(_ context.Context, shortID []byte) (adapter.UserID, error) {
		if len(shortID) != 8 {
			return adapter.UserID{}, adapter.ErrUnknownUser
		}
		var key [8]byte
		copy(key[:], shortID)
		uid, ok := t[key]
		if !ok {
			return adapter.UserID{}, adapter.ErrUnknownUser
		}
		return uid, nil
	}), nil
}
