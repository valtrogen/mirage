package config

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/valtrogen/mirage/adapter"
	"github.com/valtrogen/mirage/recycle"
)

const validMaster = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func TestLoadReaderMinimalSucceeds(t *testing.T) {
	in := `
listen     = "0.0.0.0:443"
master_key = "` + validMaster + `"
`
	m, err := LoadReader(strings.NewReader(in), "minimal")
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	if m.Listen != "0.0.0.0:443" {
		t.Fatalf("listen = %q", m.Listen)
	}
	if len(m.MasterKey) != 32 {
		t.Fatalf("master key wrong length: %d", len(m.MasterKey))
	}
	if got := recycle.DefaultBounds(); m.RecycleBounds != got {
		t.Fatalf("recycle bounds default mismatch: got %+v want %+v", m.RecycleBounds, got)
	}
	if m.Authenticator != nil {
		t.Fatalf("Authenticator should be nil when no users")
	}
	if m.SNITargets != nil {
		t.Fatalf("SNITargets should be nil when no entries")
	}
}

func TestLoadReaderRequiresListen(t *testing.T) {
	_, err := LoadReader(strings.NewReader(`master_key = "`+validMaster+`"`), "x")
	if err == nil || !strings.Contains(err.Error(), "listen") {
		t.Fatalf("expected listen-required error, got %v", err)
	}
}

func TestLoadReaderRequiresMasterKey(t *testing.T) {
	_, err := LoadReader(strings.NewReader(`listen = "127.0.0.1:1"`), "x")
	if err == nil || !strings.Contains(err.Error(), "master_key") {
		t.Fatalf("expected master_key-required error, got %v", err)
	}
}

func TestLoadReaderRejectsShortMasterKey(t *testing.T) {
	in := `
listen     = "127.0.0.1:1"
master_key = "deadbeef"
`
	_, err := LoadReader(strings.NewReader(in), "x")
	if err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Fatalf("expected length error, got %v", err)
	}
}

func TestLoadReaderRejectsBothKeyForms(t *testing.T) {
	in := `
listen          = "127.0.0.1:1"
master_key      = "` + validMaster + `"
master_key_file = "/tmp/x"
`
	_, err := LoadReader(strings.NewReader(in), "x")
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("expected mutual-exclusion error, got %v", err)
	}
}

func TestLoadKeyFromFile(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "mk.hex")
	if err := os.WriteFile(keyPath, []byte(validMaster+"\n"), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	in := `
listen          = "127.0.0.1:1"
master_key_file = "` + keyPath + `"
`
	m, err := LoadReader(strings.NewReader(in), "x")
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	want, _ := hex.DecodeString(validMaster)
	if string(m.MasterKey) != string(want) {
		t.Fatalf("master key mismatch")
	}
}

func TestRecycleOverridesAndValidation(t *testing.T) {
	in := `
listen     = "127.0.0.1:1"
master_key = "` + validMaster + `"

[recycle]
age_min   = "10m"
age_max   = "20m"
bytes_min = 1024
bytes_max = 2048
`
	m, err := LoadReader(strings.NewReader(in), "x")
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	if m.RecycleBounds.AgeMin != 10*time.Minute || m.RecycleBounds.AgeMax != 20*time.Minute {
		t.Fatalf("age bounds: %+v", m.RecycleBounds)
	}
	if m.RecycleBounds.BytesMin != 1024 || m.RecycleBounds.BytesMax != 2048 {
		t.Fatalf("byte bounds: %+v", m.RecycleBounds)
	}

	bad := `
listen     = "127.0.0.1:1"
master_key = "` + validMaster + `"

[recycle]
age_min = "30m"
age_max = "10m"
`
	if _, err := LoadReader(strings.NewReader(bad), "x"); err == nil ||
		!strings.Contains(err.Error(), "age_min > age_max") {
		t.Fatalf("expected bounds error, got %v", err)
	}
}

func TestUserTableAuthenticator(t *testing.T) {
	in := `
listen     = "127.0.0.1:1"
master_key = "` + validMaster + `"

[[user]]
short_id = "1111111111111111"
uid_hex  = "01"

[[user]]
short_id = "2222222222222222"
uid_hex  = "020304"
`
	m, err := LoadReader(strings.NewReader(in), "x")
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	if m.Authenticator == nil {
		t.Fatal("Authenticator nil")
	}
	good, _ := hex.DecodeString("1111111111111111")
	uid, err := m.Authenticator.Verify(context.Background(), good)
	if err != nil {
		t.Fatalf("Verify good: %v", err)
	}
	if uid[0] != 0x01 {
		t.Fatalf("uid[0] = %#x", uid[0])
	}

	if _, err := m.Authenticator.Verify(context.Background(), make([]byte, 8)); err != adapter.ErrUnknownUser {
		t.Fatalf("expected ErrUnknownUser, got %v", err)
	}
	if _, err := m.Authenticator.Verify(context.Background(), []byte{1, 2, 3}); err != adapter.ErrUnknownUser {
		t.Fatalf("expected ErrUnknownUser for short id, got %v", err)
	}
}

func TestUserTableRejectsBadHex(t *testing.T) {
	in := `
listen     = "127.0.0.1:1"
master_key = "` + validMaster + `"

[[user]]
short_id = "ZZ"
uid_hex  = "01"
`
	if _, err := LoadReader(strings.NewReader(in), "x"); err == nil {
		t.Fatalf("expected error for bad short_id hex")
	}
}

func TestSNITableMaterialises(t *testing.T) {
	in := `
listen     = "127.0.0.1:1"
master_key = "` + validMaster + `"

[[sni_target]]
name = "www.example.com"
host = "1.1.1.1"
port = 443
`
	m, err := LoadReader(strings.NewReader(in), "x")
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	if m.SNITargets == nil {
		t.Fatal("SNITargets nil")
	}
	host, port, err := m.SNITargets.ResolveRealTarget(context.Background(), "www.example.com")
	if err != nil {
		t.Fatalf("ResolveRealTarget: %v", err)
	}
	if host != "1.1.1.1" || port != 443 {
		t.Fatalf("target = %s:%d", host, port)
	}
}

func TestSNITableRejectsMissingFields(t *testing.T) {
	in := `
listen     = "127.0.0.1:1"
master_key = "` + validMaster + `"

[[sni_target]]
name = "x"
host = ""
port = 0
`
	if _, err := LoadReader(strings.NewReader(in), "x"); err == nil {
		t.Fatalf("expected error for incomplete sni_target")
	}
}

func TestDurationsParseAndError(t *testing.T) {
	in := `
listen        = "127.0.0.1:1"
master_key    = "` + validMaster + `"
session_ttl   = "30s"
drain         = "5s"
`
	m, err := LoadReader(strings.NewReader(in), "x")
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	if m.SessionTTL != 30*time.Second {
		t.Fatalf("ttl = %v", m.SessionTTL)
	}
	if m.Drain != 5*time.Second {
		t.Fatalf("drain = %v", m.Drain)
	}

	bad := `
listen     = "127.0.0.1:1"
master_key = "` + validMaster + `"
drain      = "not-a-duration"
`
	if _, err := LoadReader(strings.NewReader(bad), "x"); err == nil {
		t.Fatalf("expected duration parse error")
	}
}

func TestAdditionalMasterKeys(t *testing.T) {
	second := make([]byte, 32)
	rand.Read(second)
	in := `
listen                 = "127.0.0.1:1"
master_key             = "` + validMaster + `"
additional_master_keys = ["` + hex.EncodeToString(second) + `"]
`
	m, err := LoadReader(strings.NewReader(in), "x")
	if err != nil {
		t.Fatalf("LoadReader: %v", err)
	}
	if len(m.AdditionalMasterKeys) != 1 || len(m.AdditionalMasterKeys[0]) != 32 {
		t.Fatalf("additional master keys mis-parsed: %#v", m.AdditionalMasterKeys)
	}
}

func TestLoadFileReadsFromDisk(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "m.toml")
	body := `
listen     = "127.0.0.1:1"
master_key = "` + validMaster + `"
`
	if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := LoadFile(cfg); err != nil {
		t.Fatalf("LoadFile: %v", err)
	}
	if _, err := LoadFile(filepath.Join(dir, "missing.toml")); err == nil {
		t.Fatalf("expected error for missing file")
	}
}
