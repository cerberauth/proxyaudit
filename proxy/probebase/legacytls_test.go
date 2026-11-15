package probebase_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

func record(contentType byte, payload []byte) []byte {
	out := []byte{contentType, 0x03, 0x03}
	out = binary.BigEndian.AppendUint16(out, uint16(len(payload))) //nolint:gosec
	return append(out, payload...)
}

func handshake(msgType byte, body []byte) []byte {
	return append([]byte{msgType, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...) //nolint:gosec
}

func serverHello(version, suite uint16) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, suite)
	body = append(body, 0)
	return handshake(0x02, body)
}

func serverKeyExchange(primeBytes int) []byte {
	prime := bytes.Repeat([]byte{0xff}, primeBytes)
	body := binary.BigEndian.AppendUint16(nil, uint16(len(prime))) //nolint:gosec
	body = append(body, prime...)
	body = append(body, 0x00, 0x01, 0x02, 0x00, 0x01, 0x05)
	return handshake(0x0c, body)
}

func TestReadLegacyServerHello(t *testing.T) {
	dhe := append(serverHello(probebase.VersionTLS12, 0x0033), handshake(0x0b, []byte{0, 0, 0})...)
	dhe = append(dhe, serverKeyExchange(128)...)

	testCases := []struct {
		name     string
		response []byte
		expected *probebase.LegacyHello
		err      error
	}{
		{"SSL 3.0 accepted", record(0x16, serverHello(probebase.VersionSSL30, 0x000a)), &probebase.LegacyHello{Version: probebase.VersionSSL30, CipherSuite: 0x000a}, nil},
		{"DHE fragmented across records", append(record(0x16, dhe[:20]), record(0x16, dhe[20:])...), &probebase.LegacyHello{Version: probebase.VersionTLS12, CipherSuite: 0x0033, DHPrimeBits: 1024}, nil},
		{"alert", record(0x15, []byte{0x02, 0x28}), nil, probebase.ErrHandshakeRejected},
		{"connection closed", nil, nil, probebase.ErrHandshakeRejected},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			hello, err := probebase.ReadLegacyServerHello(bytes.NewReader(tc.response))

			if tc.err != nil {
				assert.ErrorIs(t, err, tc.err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.expected, hello)
		})
	}
}

func TestBuildClientHello(t *testing.T) {
	hello, err := probebase.BuildClientHello(probebase.VersionSSL30, []uint16{0x000a}, "example.com")
	require.NoError(t, err)

	assert.Equal(t, byte(0x16), hello[0])
	assert.Equal(t, probebase.VersionSSL30, binary.BigEndian.Uint16(hello[1:3]))
	assert.Equal(t, byte(0x01), hello[5])
	assert.Equal(t, probebase.VersionSSL30, binary.BigEndian.Uint16(hello[9:11]))
	assert.NotContains(t, string(hello), "example.com")

	hello, err = probebase.BuildClientHello(probebase.VersionTLS12, probebase.DHESuites, "example.com")
	require.NoError(t, err)
	assert.Equal(t, uint16(0x0301), binary.BigEndian.Uint16(hello[1:3]))
	assert.Contains(t, string(hello), "example.com")
}

func TestProbeLegacyHello(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		header := make([]byte, 5)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		_, _ = io.ReadFull(conn, make([]byte, binary.BigEndian.Uint16(header[3:5])))
		_, _ = conn.Write(record(0x16, serverHello(probebase.VersionSSL30, 0x0005)))
	}()

	hello, err := probebase.ProbeLegacyHello(context.Background(), listener.Addr().String(), probebase.VersionSSL30, probebase.SSL3Suites)

	require.NoError(t, err)
	assert.Equal(t, probebase.VersionSSL30, hello.Version)
	assert.Equal(t, uint16(0x0005), hello.CipherSuite)
}
