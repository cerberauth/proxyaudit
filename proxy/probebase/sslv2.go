package probebase

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	sslv2ClientHello = 0x01
	sslv2ServerHello = 0x04
	versionSSL20     = 0x0002
)

var SSLv2CipherSpecs = [][3]byte{
	{0x01, 0x00, 0x80},
	{0x02, 0x00, 0x80},
	{0x03, 0x00, 0x80},
	{0x04, 0x00, 0x80},
	{0x05, 0x00, 0x80},
	{0x06, 0x00, 0x40},
	{0x07, 0x00, 0xc0},
}

type SSLv2Hello struct {
	CipherSpecs int
}

func BuildSSLv2ClientHello() ([]byte, error) {
	challenge := make([]byte, 16)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	body := []byte{sslv2ClientHello}
	body = appendUint16(body, versionSSL20)
	body = appendUint16(body, uint16(3*len(SSLv2CipherSpecs))) //nolint:gosec
	body = appendUint16(body, 0)
	body = appendUint16(body, uint16(len(challenge))) //nolint:gosec
	for _, spec := range SSLv2CipherSpecs {
		body = append(body, spec[:]...)
	}
	body = append(body, challenge...)
	return append(appendUint16(nil, 0x8000|uint16(len(body))), body...), nil //nolint:gosec
}

func ProbeSSLv2(ctx context.Context, host string) (*SSLv2Hello, error) {
	hello, err := BuildSSLv2ClientHello()
	if err != nil {
		return nil, err
	}
	conn, err := dialRaw(ctx, host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if _, err := conn.Write(hello); err != nil {
		return nil, err
	}
	return ReadSSLv2ServerHello(conn)
}

func ReadSSLv2ServerHello(r io.Reader) (*SSLv2Hello, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeRejected, err)
	}
	if header[0]&0x80 == 0 {
		return nil, fmt.Errorf("%w: not an SSLv2 record", ErrHandshakeRejected)
	}
	body := make([]byte, int(binary.BigEndian.Uint16(header)&0x7fff))
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrHandshakeRejected, err)
	}
	if len(body) < 11 || body[0] != sslv2ServerHello {
		return nil, fmt.Errorf("%w: not an SSLv2 server hello", ErrHandshakeRejected)
	}
	if binary.BigEndian.Uint16(body[3:5]) != versionSSL20 {
		return nil, errors.New("unexpected SSLv2 server hello version")
	}
	return &SSLv2Hello{CipherSpecs: int(binary.BigEndian.Uint16(body[7:9])) / 3}, nil
}
