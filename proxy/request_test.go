package proxy

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRequestRoundTripIPv4(t *testing.T) {
	in := Request{Cmd: CmdTCPConnect, Host: "192.0.2.1", Port: 443}
	buf, err := in.AppendBytes(nil)
	if err != nil {
		t.Fatalf("AppendBytes: %v", err)
	}
	got, err := ReadRequest(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if got != in {
		t.Fatalf("got %+v want %+v", got, in)
	}
}

func TestRequestRoundTripIPv6(t *testing.T) {
	in := Request{Cmd: CmdTCPConnect, Host: "2001:db8::1", Port: 80}
	buf, err := in.AppendBytes(nil)
	if err != nil {
		t.Fatalf("AppendBytes: %v", err)
	}
	got, err := ReadRequest(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if got != in {
		t.Fatalf("got %+v want %+v", got, in)
	}
}

func TestRequestRoundTripDomain(t *testing.T) {
	in := Request{Cmd: CmdTCPConnect, Host: "example.com", Port: 8443}
	buf, err := in.AppendBytes(nil)
	if err != nil {
		t.Fatalf("AppendBytes: %v", err)
	}
	got, err := ReadRequest(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("ReadRequest: %v", err)
	}
	if got != in {
		t.Fatalf("got %+v want %+v", got, in)
	}
}

func TestRequestDomainAtMaxLength(t *testing.T) {
	host := strings.Repeat("a", maxDomainLen)
	in := Request{Cmd: CmdTCPConnect, Host: host, Port: 1}
	buf, err := in.AppendBytes(nil)
	if err != nil {
		t.Fatalf("AppendBytes: %v", err)
	}
	got, err := ReadRequest(bytes.NewReader(buf))
	if err != nil || got.Host != host {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestRequestDomainTooLong(t *testing.T) {
	in := Request{Cmd: CmdTCPConnect, Host: strings.Repeat("a", maxDomainLen+1), Port: 1}
	if _, err := in.AppendBytes(nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v want ErrProtocol", err)
	}
}

func TestRequestEmptyHostRejectedOnEncode(t *testing.T) {
	in := Request{Cmd: CmdTCPConnect, Host: "", Port: 1}
	if _, err := in.AppendBytes(nil); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v want ErrProtocol", err)
	}
}

func TestReadRequestRejectsZeroLengthDomain(t *testing.T) {
	buf := []byte{ProtoVersion, byte(CmdTCPConnect), byte(AddrDomain), 0x00, 0x50, 0x00}
	if _, err := ReadRequest(bytes.NewReader(buf)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v want ErrProtocol", err)
	}
}

func TestReadRequestRejectsBadVersion(t *testing.T) {
	buf := []byte{0xFF, byte(CmdTCPConnect), byte(AddrIPv4), 0x00, 0x50, 1, 2, 3, 4}
	if _, err := ReadRequest(bytes.NewReader(buf)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v want ErrProtocol", err)
	}
}

func TestReadRequestRejectsUnknownAddrType(t *testing.T) {
	buf := []byte{ProtoVersion, byte(CmdTCPConnect), 0x09, 0x00, 0x50}
	if _, err := ReadRequest(bytes.NewReader(buf)); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v want ErrProtocol", err)
	}
}

func TestReadRequestTruncatedHeader(t *testing.T) {
	if _, err := ReadRequest(bytes.NewReader([]byte{ProtoVersion, 0x01})); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err=%v want ErrUnexpectedEOF", err)
	}
}

func TestReadRequestTruncatedDomain(t *testing.T) {
	buf := []byte{ProtoVersion, byte(CmdTCPConnect), byte(AddrDomain), 0x00, 0x50, 0x05, 'a', 'b'}
	if _, err := ReadRequest(bytes.NewReader(buf)); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("err=%v want ErrUnexpectedEOF", err)
	}
}

func TestResponseRoundTripOK(t *testing.T) {
	in := Response{Status: StatusOK}
	got, err := ReadResponse(bytes.NewReader(in.AppendBytes(nil)))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if got != in {
		t.Fatalf("got %+v want %+v", got, in)
	}
}

func TestResponseRoundTripWithReason(t *testing.T) {
	in := Response{Status: StatusConnRefused, Reason: "dial tcp 127.0.0.1:1: connection refused"}
	got, err := ReadResponse(bytes.NewReader(in.AppendBytes(nil)))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if got != in {
		t.Fatalf("got %+v want %+v", got, in)
	}
}

func TestResponseReasonTruncated(t *testing.T) {
	long := strings.Repeat("x", maxReasonLen+10)
	got, err := ReadResponse(bytes.NewReader(Response{Status: StatusGeneralFail, Reason: long}.AppendBytes(nil)))
	if err != nil {
		t.Fatalf("ReadResponse: %v", err)
	}
	if len(got.Reason) != maxReasonLen {
		t.Fatalf("reason len=%d want %d", len(got.Reason), maxReasonLen)
	}
}

func TestReadResponseBadVersion(t *testing.T) {
	if _, err := ReadResponse(bytes.NewReader([]byte{0x09, 0x00, 0x00})); !errors.Is(err, ErrProtocol) {
		t.Fatalf("err=%v want ErrProtocol", err)
	}
}

func TestStatusStringIsStable(t *testing.T) {
	cases := map[Status]string{
		StatusOK:             "ok",
		StatusGeneralFail:    "general failure",
		StatusBadRequest:     "bad request",
		StatusConnRefused:    "connection refused",
		StatusNetworkUnreach: "network unreachable",
		StatusHostUnreach:    "host unreachable",
		StatusNotAllowed:     "not allowed",
		StatusTTLExpired:     "ttl expired",
	}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Fatalf("%d: got %q want %q", s, got, want)
		}
	}
	if !strings.HasPrefix(Status(0xAB).String(), "status(") {
		t.Fatalf("unknown status formatting changed")
	}
}

func TestErrorMessage(t *testing.T) {
	if msg := (&Error{Status: StatusConnRefused, Reason: "x"}).Error(); !strings.Contains(msg, "connection refused") || !strings.Contains(msg, "x") {
		t.Fatalf("Error message %q", msg)
	}
	if msg := (&Error{Status: StatusOK}).Error(); !strings.Contains(msg, "ok") {
		t.Fatalf("Error message %q", msg)
	}
}
