package adapter

import (
	"context"
	"errors"
)

// ErrNoSNITarget is returned by ResolveRealTarget when no real backend
// is configured for the requested SNI. The mirage server then drops the
// unauthenticated packet instead of forwarding it.
var ErrNoSNITarget = errors.New("mirage: no real target for SNI")

// SNITargetProvider supplies the pool of real TLS endpoints used by
// mirage to forward unauthenticated probes.
//
// Pool returns the SNI strings that authorised clients are expected to
// pick from when building their ClientHello.
//
// ResolveRealTarget maps an SNI to the actual (host, port) of a real
// backend. Lookups happen on the connection-establishment path and
// should be O(1).
type SNITargetProvider interface {
	Pool() []string
	ResolveRealTarget(ctx context.Context, sni string) (host string, port uint16, err error)
}

// StaticSNITargetProvider is an SNITargetProvider backed by a fixed map.
type StaticSNITargetProvider struct {
	Targets map[string]StaticTarget
}

// StaticTarget is one entry in a StaticSNITargetProvider.
type StaticTarget struct {
	Host string
	Port uint16
}

// Pool returns the SNI keys in the map.
func (p *StaticSNITargetProvider) Pool() []string {
	out := make([]string, 0, len(p.Targets))
	for sni := range p.Targets {
		out = append(out, sni)
	}
	return out
}

// ResolveRealTarget implements SNITargetProvider.
func (p *StaticSNITargetProvider) ResolveRealTarget(_ context.Context, sni string) (string, uint16, error) {
	t, ok := p.Targets[sni]
	if !ok {
		return "", 0, ErrNoSNITarget
	}
	return t.Host, t.Port, nil
}
