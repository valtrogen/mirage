module github.com/valtrogen/mirage

go 1.24.0

toolchain go1.24.4

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/quic-go/quic-go v0.59.0
	github.com/refraction-networking/uquic v0.0.0-00010101000000-000000000000
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/crypto v0.41.0
)

require (
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/gopacket v1.1.19 // indirect
	github.com/google/pprof v0.0.0-20250501235452-c0086092b71a // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/onsi/ginkgo/v2 v2.23.4 // indirect
	github.com/refraction-networking/clienthellod v0.5.0-alpha2 // indirect
	go.uber.org/automaxprocs v1.6.0 // indirect
	go.uber.org/mock v0.5.2 // indirect
	golang.org/x/exp v0.0.0-20250506013437-ce4c2cf36ca6 // indirect
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/tools v0.36.0 // indirect
)

// Mirage carries a small patch on top of refraction-networking/uquic:
// it exposes a PostApplyPreset hook on QUICSpec so we can re-inject
// legacy_session_id (mirage's covert auth channel) after uTLS would
// otherwise zero it per RFC 9001 §8.4. The patched source lives under
// _vendor/uquic; see _vendor/uquic/MIRAGE_PATCH.md for the diff scope.
replace github.com/refraction-networking/uquic => ./_vendor/uquic
