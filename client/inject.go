package client

import (
	"errors"
	"reflect"
	"unsafe"

	utls "github.com/refraction-networking/utls"
)

// injectSessionID overwrites the legacy_session_id field on the
// freshly-built ClientHello. uTLS's QUIC code path zeros the session
// id (per RFC 9001 §8.4); mirage repurposes the field as a covert auth
// channel, so we set it back via reflection.
//
// We also pin clientHelloBuildStatus to its "built by uTLS" value so
// the second ApplyPreset that uTLS would otherwise run inside
// BuildHandshakeState does not overwrite our SessionId again.
func injectSessionID(uqc *utls.UQUICConn, sid []byte) error {
	if uqc == nil {
		return errors.New("mirage/client: nil UQUICConn")
	}
	uconn, err := unwrapUQUICConn(uqc)
	if err != nil {
		return err
	}
	if uconn.HandshakeState.Hello == nil {
		return errors.New("mirage/client: HandshakeState.Hello nil")
	}
	uconn.HandshakeState.Hello.SessionId = append([]byte(nil), sid...)
	return pinClientHelloBuilt(uconn)
}

// unwrapUQUICConn reaches into the unexported `conn` field of
// utls.UQUICConn so we can edit the ClientHello uTLS already built.
// uTLS exposes no public accessor, so reflection + unsafe is the only
// option. The field name is part of utls's public ABI in practice;
// Mirage pins a vendored utls version (see go.mod) so this stays
// stable.
func unwrapUQUICConn(uqc *utls.UQUICConn) (*utls.UConn, error) {
	v := reflect.ValueOf(uqc).Elem().FieldByName("conn")
	if !v.IsValid() || v.Kind() != reflect.Ptr {
		return nil, errors.New("mirage/client: UQUICConn.conn not found")
	}
	uconn := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem().Interface().(*utls.UConn)
	if uconn == nil {
		return nil, errors.New("mirage/client: UQUICConn.conn nil")
	}
	return uconn, nil
}

// pinClientHelloBuilt flips the internal clientHelloBuildStatus to the
// "built by uTLS" sentinel so the next call to BuildHandshakeState
// does not re-run ApplyPreset and zero our SessionId again.
func pinClientHelloBuilt(uconn *utls.UConn) error {
	v := reflect.ValueOf(uconn).Elem().FieldByName("clientHelloBuildStatus")
	if !v.IsValid() {
		return errors.New("mirage/client: clientHelloBuildStatus field missing")
	}
	target := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
	target.SetInt(int64(utls.BuildByUtls))
	return nil
}
