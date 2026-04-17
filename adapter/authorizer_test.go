package adapter

import (
	"context"
	"errors"
	"testing"
)

func TestAllowAllProxyAuthorizerPermits(t *testing.T) {
	var a AllowAllProxyAuthorizer
	if err := a.AuthorizeTCP(context.Background(), UserID{1}, "example.com", 443); err != nil {
		t.Fatalf("AllowAll denied: %v", err)
	}
}

func TestProxyAuthorizerFuncDelegates(t *testing.T) {
	var sawHost string
	var sawPort uint16
	denial := errors.New("denied")
	f := ProxyAuthorizerFunc(func(_ context.Context, _ UserID, host string, port uint16) error {
		sawHost = host
		sawPort = port
		return denial
	})
	err := f.AuthorizeTCP(context.Background(), UserID{2}, "h", 80)
	if !errors.Is(err, denial) {
		t.Fatalf("err=%v want denial", err)
	}
	if sawHost != "h" || sawPort != 80 {
		t.Fatalf("call recorded host=%q port=%d", sawHost, sawPort)
	}
}
