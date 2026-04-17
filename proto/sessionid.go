package proto

// Layout of the 32-byte TLS 1.3 legacy_session_id field used by mirage:
//
//	offset  size  field
//	     0     4  WindowID  (big-endian uint32, low 32 bits of t)
//	     4     8  ShortID   (AES-128-GCM ciphertext)
//	    12     4  Nonce     (per-handshake random)
//	    16    16  AuthTag   (AES-128-GCM tag over bytes 0..16)
//
// The first 4 bytes are unencrypted so a pre-parse stage can drop
// stale-window packets without running AES-GCM. They are also fed to
// AES-GCM as additional data, so tampering fails verification.
const (
	SessionIDLen = 32

	SessionIDWindowOffset = 0
	SessionIDWindowLen    = 4

	SessionIDShortIDOffset = 4
	SessionIDShortIDLen    = 8

	SessionIDNonceOffset = 12
	SessionIDNonceLen    = 4

	SessionIDTagOffset = 16
	SessionIDTagLen    = 16
)

// WindowSeconds is the duration of one mirage time window in seconds.
// 90 s tolerates roughly +/- 45 s of clock skew between client and server.
const WindowSeconds = 90
