package client

import (
	"errors"
	"reflect"
	"unsafe"

	utls "github.com/refraction-networking/utls"
)

// injectSessionID overwrites the legacy_session_id field in the
// ClientHello held by uqc with sid. uTLS's QUIC code path zeros the
// session id (per RFC 9001 §8.4); mirage repurposes the field as a
// covert auth channel, so we set it back after ApplyPreset and before
// Start.
//
// We also need to suppress the second ApplyPreset that uTLS would
// otherwise run inside BuildHandshakeState (it would overwrite our
// SessionId again). To do that we set the unexported
// clientHelloBuildStatus field to its "built by uTLS" value via
// reflection.
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
	if err := pinClientHelloBuilt(uconn); err != nil {
		return err
	}
	return nil
}

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

// overrideALPN rewrites every ALPNExtension entry in spec to advertise
// alpn instead of whatever the parrot preset hardcoded (e.g. h2 for the
// standard Chrome stable spec).
func overrideALPN(spec *utls.ClientHelloSpec, alpn []string) {
	for i, ext := range spec.Extensions {
		if _, ok := ext.(*utls.ALPNExtension); ok {
			spec.Extensions[i] = &utls.ALPNExtension{AlpnProtocols: append([]string(nil), alpn...)}
		}
	}
}

// quicTransportParametersExtID is the IANA-assigned TLS extension ID
// for quic_transport_parameters (RFC 9001 §8.2).
const quicTransportParametersExtID uint16 = 57

// addQUICTransportParameters appends a quic_transport_parameters TLS
// extension carrying tp to spec. uTLS's QUIC mode does not splice the
// value provided via SetTransportParameters into spec-built ClientHellos
// (see u_quic.go SetTransportParameters comment), so we add it
// explicitly via a GenericExtension wrapper.
func addQUICTransportParameters(spec *utls.ClientHelloSpec, tp []byte) {
	for _, ext := range spec.Extensions {
		if ge, ok := ext.(*utls.GenericExtension); ok && ge.Id == quicTransportParametersExtID {
			ge.Data = append(ge.Data[:0], tp...)
			return
		}
	}
	spec.Extensions = append(spec.Extensions, &utls.GenericExtension{
		Id:   quicTransportParametersExtID,
		Data: append([]byte(nil), tp...),
	})
}

// restrictToTLS13 rewrites SupportedVersionsExtension to drop legacy
// TLS versions. QUIC (RFC 9001 §4.2) forbids offering anything older
// than TLS 1.3, and real Chrome HTTP/3 ClientHellos already do this.
func restrictToTLS13(spec *utls.ClientHelloSpec) {
	for i, ext := range spec.Extensions {
		sv, ok := ext.(*utls.SupportedVersionsExtension)
		if !ok {
			continue
		}
		filtered := make([]uint16, 0, len(sv.Versions))
		for _, v := range sv.Versions {
			if v == utls.VersionTLS12 || v == utls.VersionTLS11 || v == utls.VersionTLS10 {
				continue
			}
			filtered = append(filtered, v)
		}
		spec.Extensions[i] = &utls.SupportedVersionsExtension{Versions: filtered}
	}
}

func pinClientHelloBuilt(uconn *utls.UConn) error {
	v := reflect.ValueOf(uconn).Elem().FieldByName("clientHelloBuildStatus")
	if !v.IsValid() {
		return errors.New("mirage/client: clientHelloBuildStatus field missing")
	}
	target := reflect.NewAt(v.Type(), unsafe.Pointer(v.UnsafeAddr())).Elem()
	target.SetInt(int64(utls.BuildByUtls))
	return nil
}
