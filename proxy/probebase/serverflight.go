package probebase

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	recordChangeCipherSpec = 0x14
	recordHeartbeat        = 0x18

	handshakeCertificate       = 0x0b
	handshakeClientKeyExchange = 0x10
)

type ServerFlight struct {
	Version      uint16
	CipherSuite  uint16
	Extensions   map[uint16][]byte
	Certificates [][]byte
}

func ReadServerFlight(r io.Reader) (*ServerFlight, error) {
	r = io.LimitReader(r, maxLegacyResponse)
	var flight *ServerFlight
	var buffer []byte
	header := make([]byte, 5)
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrHandshakeRejected, err)
		}
		payload := make([]byte, binary.BigEndian.Uint16(header[3:5]))
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrHandshakeRejected, err)
		}
		if header[0] != recordHandshake {
			return nil, fmt.Errorf("%w: record type %d", ErrHandshakeRejected, header[0])
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
				parsed, err := parseServerHelloExtensions(msg)
				if err != nil {
					return nil, err
				}
				flight = parsed
			case handshakeCertificate:
				if flight == nil {
					return nil, errors.New("certificate before server hello")
				}
				certificates, err := parseCertificateList(msg)
				if err != nil {
					return nil, err
				}
				flight.Certificates = certificates
			case handshakeServerHelloDone:
				if flight == nil {
					return nil, errors.New("server hello done before server hello")
				}
				return flight, nil
			}
		}
	}
}

func parseServerHelloExtensions(msg []byte) (*ServerFlight, error) {
	hello, err := parseServerHello(msg)
	if err != nil {
		return nil, err
	}
	flight := &ServerFlight{Version: hello.Version, CipherSuite: hello.CipherSuite, Extensions: map[uint16][]byte{}}
	offset := 35 + int(msg[34]) + 3
	if len(msg) < offset+2 {
		return flight, nil
	}
	rest := msg[offset:]
	extensions := rest[2:]
	if length := int(binary.BigEndian.Uint16(rest)); length < len(extensions) {
		extensions = extensions[:length]
	}
	for len(extensions) >= 4 {
		extType := binary.BigEndian.Uint16(extensions)
		length := int(binary.BigEndian.Uint16(extensions[2:]))
		if len(extensions) < 4+length {
			break
		}
		flight.Extensions[extType] = extensions[4 : 4+length]
		extensions = extensions[4+length:]
	}
	return flight, nil
}

func parseCertificateList(msg []byte) ([][]byte, error) {
	if len(msg) < 3 {
		return nil, errors.New("short certificate message")
	}
	list := msg[3:]
	var certificates [][]byte
	for len(list) >= 3 {
		length := int(list[0])<<16 | int(list[1])<<8 | int(list[2])
		if len(list) < 3+length {
			return nil, errors.New("short certificate entry")
		}
		certificates = append(certificates, list[3:3+length])
		list = list[3+length:]
	}
	return certificates, nil
}

func appendRecord(b []byte, contentType byte, version uint16, payload []byte) []byte {
	b = append(b, contentType)
	b = appendUint16(b, version)
	b = appendUint16(b, uint16(len(payload))) //nolint:gosec
	return append(b, payload...)
}
