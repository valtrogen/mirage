package adapter

import (
	"context"
	"errors"
)

// ErrConnectionNotAllowed is returned by ProxyAuthorizer when a target
// is rejected by policy. Implementations may wrap this error to attach
// a human-readable reason.
var ErrConnectionNotAllowed = errors.New("mirage: connection not allowed by policy")

// ProxyAuthorizer decides whether an authenticated user may open a
// proxied TCP connection to (host, port).
//
// host is the literal string the client requested. It is typically a
// domain name or an IP literal. mirage performs no DNS lookup before
// calling AuthorizeTCP, so an implementation that needs to enforce a
// numeric IP allow-list MUST resolve host itself. Keeping DNS policy
// in the operator's hands prevents accidental data-plane DNS leaks.
//
// AuthorizeTCP returns nil to permit the connection, or an error to
// deny. The error text is sent back to the client in the response
// frame, so it should not contain secrets.
//
// AuthorizeUDP is consulted once per outbound UDP datagram during a
// CmdUDPAssociate stream. Implementations are expected to short-cut
// repeated calls for the same (uid, host, port) tuple if their policy
// permits caching; mirage performs no caching of its own so policy
// can express "first packet only" or "every packet" semantics.
type ProxyAuthorizer interface {
	AuthorizeTCP(ctx context.Context, uid UserID, host string, port uint16) error
	AuthorizeUDP(ctx context.Context, uid UserID, host string, port uint16) error
}

// AllowAllProxyAuthorizer permits every request unconditionally. It is
// intended for development binaries and tests; production deployments
// MUST replace it with a policy-aware implementation.
type AllowAllProxyAuthorizer struct{}

// AuthorizeTCP implements ProxyAuthorizer.
func (AllowAllProxyAuthorizer) AuthorizeTCP(context.Context, UserID, string, uint16) error {
	return nil
}

// AuthorizeUDP implements ProxyAuthorizer.
func (AllowAllProxyAuthorizer) AuthorizeUDP(context.Context, UserID, string, uint16) error {
	return nil
}

// ProxyAuthorizerFunc adapts a plain function to ProxyAuthorizer. The
// same function is consulted for both TCP and UDP. Callers that need
// to discriminate by transport should switch on a ctx value or wrap
// the func type themselves.
type ProxyAuthorizerFunc func(ctx context.Context, uid UserID, host string, port uint16) error

// AuthorizeTCP implements ProxyAuthorizer.
func (f ProxyAuthorizerFunc) AuthorizeTCP(ctx context.Context, uid UserID, host string, port uint16) error {
	return f(ctx, uid, host, port)
}

// AuthorizeUDP implements ProxyAuthorizer.
func (f ProxyAuthorizerFunc) AuthorizeUDP(ctx context.Context, uid UserID, host string, port uint16) error {
	return f(ctx, uid, host, port)
}
