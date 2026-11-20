package probebase

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	VersionSSL30 uint16 = 0x0300
	VersionTLS12 uint16 = 0x0303
)

var (
	RC4Suites  = []uint16{0x0004, 0x0005, 0xc007, 0xc011}
	TDESSuites = []uint16{0x000a, 0x0016, 0xc012}
	NULLSuites = []uint16{0x0001, 0x0002, 0x003b, 0xc010}
	DHESuites  = []uint16{0x0033, 0x0039, 0x0067, 0x006b, 0x009e, 0x009f, 0xccaa}
	SSL3Suites = []uint16{0x0004, 0x0005, 0x000a, 0x0016, 0x002f, 0x0033, 0x0035, 0x0039}
)

var ErrHandshakeRejected = errors.New("handshake rejected")

type LegacyHello struct {
	Version     uint16
	CipherSuite uint16
	DHPrimeBits int
}

const (
	recordHandshake = 0x16
	recordAlert     = 0x15

	handshakeServerHello       = 0x02
	handshakeServerKeyExchange = 0x0c
	handshakeServerHelloDone   = 0x0e

	maxLegacyResponse = 64 * 1024
)

func IsDHESuite(suite uint16) bool {
	for _, s := range DHESuites {
		if s == suite {
			return true
		}
	}
	return suite == 0x0016
}

func appendUint16(b []byte, v uint16) []byte {
	return binary.BigEndian.AppendUint16(b, v)
}

func appendUint24(b []byte, v int) []byte {
	return append(b, byte(v>>16), byte(v>>8), byte(v)) //nolint:gosec
}

func appendExtension(b []byte, extType uint16, data []byte) []byte {
	b = appendUint16(b, extType)
	b = appendUint16(b, uint16(len(data))) //nolint:gosec
	return append(b, data...)
}

func BuildClientHello(version uint16, suites []uint16, serverName string) ([]byte, error) {
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}

	body := appendUint16(nil, version)
	body = append(body, random...)
	body = append(body, 0)
	body = appendUint16(body, uint16(2*len(suites))) //nolint:gosec
	for _, s := range suites {
		body = appendUint16(body, s)
	}
	body = append(body, 1, 0)

	if version > VersionSSL30 {
		var extensions []byte
		if serverName != "" && net.ParseIP(serverName) == nil {
			name := appendUint16(nil, uint16(len(serverName)+3)) //nolint:gosec
			name = append(name, 0)
			name = appendUint16(name, uint16(len(serverName))) //nolint:gosec
			name = append(name, serverName...)
			extensions = appendExtension(extensions, 0x0000, name)
		}
		extensions = appendExtension(extensions, 0x000a, []byte{0x00, 0x06, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x18})
		extensions = appendExtension(extensions, 0x000b, []byte{0x01, 0x00})
		if version >= VersionTLS12 {
			extensions = appendExtension(extensions, 0x000d, []byte{0x00, 0x0a, 0x04, 0x01, 0x05, 0x01, 0x06, 0x01, 0x02, 0x01, 0x04, 0x03})
		}
		extensions = appendExtension(extensions, 0xff01, []byte{0x00})
		body = appendUint16(body, uint16(len(extensions))) //nolint:gosec
		body = append(body, extensions...)
	}

	handshake := append([]byte{0x01}, appendUint24(nil, len(body))...)
	handshake = append(handshake, body...)

	recordVersion := uint16(0x0301)
	if version == VersionSSL30 {
		recordVersion = VersionSSL30
	}
	record := []byte{recordHandshake}
	record = appendUint16(record, recordVersion)
	record = appendUint16(record, uint16(len(handshake))) //nolint:gosec
	return append(record, handshake...), nil
}

func ProbeLegacyHello(ctx context.Context, host string, version uint16, suites []uint16) (*LegacyHello, error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}
	hello, err := BuildClientHello(version, suites, hostname)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{Timeout: DialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(DialTimeout)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = conn.SetDeadline(deadline)

	if _, err := conn.Write(hello); err != nil {
		return nil, err
	}
	return ReadLegacyServerHello(conn)
}

func ReadLegacyServerHello(r io.Reader) (*LegacyHello, error) {
	r = io.LimitReader(r, maxLegacyResponse)
	var result *LegacyHello
	var buffer []byte
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			if result != nil {
				return result, nil
			}
			return nil, fmt.Errorf("%w: %v", ErrHandshakeRejected, err)
		}
		length := int(binary.BigEndian.Uint16(header[3:5]))
		payload := make([]byte, length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return result, nil
		}
		switch header[0] {
		case recordAlert:
			if result != nil {
				return result, nil
			}
			return nil, ErrHandshakeRejected
		case recordHandshake:
		default:
			if result != nil {
				return result, nil
			}
			return nil, fmt.Errorf("%w: unexpected record type %d", ErrHandshakeRejected, header[0])
		}

		buffer = append(buffer, payload...)
		for len(buffer) >= 4 {
			msgLength := int(buffer[1])<<16 | int(buffer[2])<<8 | int(buffer[3])
			if len(buffer) < 4+msgLength {
				break
			}
			msgType, msg := buffer[0], buffer[4:4+msgLength]
			buffer = buffer[4+msgLength:]
			switch msgType {
			case handshakeServerHello:
				hello, err := parseServerHello(msg)
				if err != nil {
					return nil, err
				}
				result = hello
				if !IsDHESuite(hello.CipherSuite) {
					return result, nil
				}
			case handshakeServerKeyExchange:
				if result != nil && len(msg) >= 2 {
					result.DHPrimeBits = primeBits(msg[2:], int(binary.BigEndian.Uint16(msg[:2])))
				}
				return result, nil
			case handshakeServerHelloDone:
				return result, nil
			}
		}
	}
}

func parseServerHello(msg []byte) (*LegacyHello, error) {
	if len(msg) < 35 {
		return nil, errors.New("short server hello")
	}
	sessionIDLength := int(msg[34])
	if len(msg) < 35+sessionIDLength+2 {
		return nil, errors.New("short server hello")
	}
	return &LegacyHello{
		Version:     binary.BigEndian.Uint16(msg[:2]),
		CipherSuite: binary.BigEndian.Uint16(msg[35+sessionIDLength:]),
	}, nil
}

func primeBits(p []byte, length int) int {
	if length > len(p) {
		length = len(p)
	}
	p = p[:length]
	for len(p) > 0 && p[0] == 0 {
		p = p[1:]
	}
	if len(p) == 0 {
		return 0
	}
	bits := 8 * len(p)
	for b := p[0]; b&0x80 == 0; b <<= 1 {
		bits--
	}
	return bits
}
