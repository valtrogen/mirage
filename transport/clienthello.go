package transport

import "errors"

var (
	// ErrNotClientHello is returned when the input is not a TLS 1.3
	// Handshake message of type ClientHello (0x01).
	ErrNotClientHello = errors.New("mirage: not a TLS ClientHello")

	// ErrTruncatedClientHello is returned when the ClientHello body is
	// shorter than its declared length or one of its sub-fields.
	ErrTruncatedClientHello = errors.New("mirage: truncated ClientHello")
)

// ExtractClientHelloSessionID returns the legacy_session_id field of a
// TLS 1.3 ClientHello carried directly in handshake bytes (i.e. starting
// with msg_type=0x01 and a 3-byte length).
//
// The returned slice may be empty if the client sent no session id.
// Callers must copy it if they intend to retain the bytes.
//
// Layout per RFC 8446 §4.1.2:
//
//	struct {
//	    HandshakeType msg_type = client_hello (1);
//	    uint24 length;
//	    ProtocolVersion legacy_version = 0x0303;
//	    Random random;                            // 32 bytes
//	    opaque legacy_session_id<0..32>;          // 1-byte length prefix
//	    ...
//	} Handshake { ClientHello };
func ExtractClientHelloSessionID(handshake []byte) ([]byte, error) {
	if len(handshake) < 4 {
		return nil, ErrTruncatedClientHello
	}
	if handshake[0] != 0x01 {
		return nil, ErrNotClientHello
	}
	bodyLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	body := handshake[4:]
	if len(body) < bodyLen {
		return nil, ErrTruncatedClientHello
	}
	body = body[:bodyLen]

	// legacy_version(2) + random(32) = 34 bytes before session_id length.
	if len(body) < 34+1 {
		return nil, ErrTruncatedClientHello
	}
	sidLen := int(body[34])
	if sidLen > 32 {
		return nil, ErrTruncatedClientHello
	}
	if len(body) < 34+1+sidLen {
		return nil, ErrTruncatedClientHello
	}
	return body[35 : 35+sidLen], nil
}
