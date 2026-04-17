package adapter

import (
	"context"
	"errors"
)

// UserID is an opaque identifier returned by a UserAuthenticator. mirage
// never inspects its contents. The zero value means "no user".
type UserID [16]byte

// IsZero reports whether u is the zero UserID.
func (u UserID) IsZero() bool {
	return u == UserID{}
}

// ErrUnknownUser is returned when a presented short-id does not match
// any active user. The mirage server treats this as the trigger to
// transparently forward the connection to a real SNI target instead
// of failing.
var ErrUnknownUser = errors.New("mirage: unknown user")

// UserAuthenticator resolves a short-id (already decrypted by mirage)
// to an opaque user identifier.
//
// Verify is called once per incoming QUIC connection. It must be fast;
// implementations should keep the lookup in memory.
//
// The shortID slice is only valid for the duration of the call.
type UserAuthenticator interface {
	Verify(ctx context.Context, shortID []byte) (UserID, error)
}

// UserAuthenticatorFunc adapts a function to UserAuthenticator.
type UserAuthenticatorFunc func(ctx context.Context, shortID []byte) (UserID, error)

// Verify implements UserAuthenticator.
func (f UserAuthenticatorFunc) Verify(ctx context.Context, shortID []byte) (UserID, error) {
	return f(ctx, shortID)
}
