package probebase_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

func serverHelloWithExtensions(version, suite uint16, extensions []byte) []byte {
	body := binary.BigEndian.AppendUint16(nil, version)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, suite)
	body = append(body, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(len(extensions))) //nolint:gosec
	body = append(body, extensions...)
	return handshake(0x02, body)
}

func certificateMessage(der []byte) []byte {
	entry := append([]byte{byte(len(der) >> 16), byte(len(der) >> 8), byte(len(der))}, der...)                        //nolint:gosec
	return handshake(0x0b, append([]byte{byte(len(entry) >> 16), byte(len(entry) >> 8), byte(len(entry))}, entry...)) //nolint:gosec
}

func readRecord(r io.Reader) (byte, []byte, error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, err
	}
	payload := make([]byte, binary.BigEndian.Uint16(header[3:5]))
	_, err := io.ReadFull(r, payload)
	return header[0], payload, err
}

func serve(t *testing.T, handler func(net.Conn)) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				handler(conn)
			}()
		}
	}()
	return listener.Addr().String()
}

func tlsServerHost(t *testing.T, config *tls.Config) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = config
	srv.StartTLS()
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	require.NoError(t, err)
	return u.Host
}

func rsaCertificate(t *testing.T) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	return key, der
}

func TestReadServerFlight(t *testing.T) {
	extensions := []byte{0x00, 0x0f, 0x00, 0x01, 0x01, 0xff, 0x01, 0x00, 0x01, 0x00}
	messages := append(serverHelloWithExtensions(probebase.VersionTLS12, 0x002f, extensions), certificateMessage([]byte{0x30, 0x00})...)
	messages = append(messages, handshake(0x0e, nil)...)

	flight, err := probebase.ReadServerFlight(bytes.NewReader(append(record(0x16, messages[:30]), record(0x16, messages[30:])...)))

	require.NoError(t, err)
	assert.Equal(t, probebase.VersionTLS12, flight.Version)
	assert.Equal(t, uint16(0x002f), flight.CipherSuite)
	assert.Equal(t, []byte{0x01}, flight.Extensions[0x000f])
	assert.Equal(t, [][]byte{{0x30, 0x00}}, flight.Certificates)

	_, err = probebase.ReadServerFlight(bytes.NewReader(record(0x15, []byte{0x02, 0x28})))
	assert.ErrorIs(t, err, probebase.ErrHandshakeRejected)
}

func TestReadHeartbeatResponse(t *testing.T) {
	testCases := []struct {
		name     string
		response []byte
		expected bool
	}{
		{"heartbeat response", append(record(0x16, []byte{0x0e, 0, 0, 0}), record(0x18, make([]byte, 35))...), true},
		{"alert", record(0x15, []byte{0x02, 0x0a}), false},
		{"connection closed", nil, false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, probebase.ReadHeartbeatResponse(bytes.NewReader(tc.response)))
		})
	}
}

func heartbleedServer(vulnerable bool) func(net.Conn) {
	return func(conn net.Conn) {
		if _, _, err := readRecord(conn); err != nil {
			return
		}
		flight := append(serverHelloWithExtensions(probebase.VersionTLS12, 0x002f, []byte{0x00, 0x0f, 0x00, 0x01, 0x01}), handshake(0x0e, nil)...)
		_, _ = conn.Write(record(0x16, flight))
		contentType, payload, err := readRecord(conn)
		if err != nil || contentType != 0x18 || !vulnerable {
			return
		}
		length := int(binary.BigEndian.Uint16(payload[1:3]))
		_, _ = conn.Write(record(0x18, append([]byte{0x02, payload[1], payload[2]}, make([]byte, length+16)...)))
	}
}

func TestProbeHeartbleed(t *testing.T) {
	testCases := []struct {
		name     string
		host     string
		expected bool
	}{
		{"vulnerable", serve(t, heartbleedServer(true)), true},
		{"heartbeat ignored", serve(t, heartbleedServer(false)), false},
		{"crypto/tls", tlsServerHost(t, nil), false},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			vulnerable, err := probebase.ProbeHeartbleed(context.Background(), tc.host)

			require.NoError(t, err)
			assert.Equal(t, tc.expected, vulnerable)
		})
	}
}

func sslv2ServerHello(cipherSpecs int) []byte {
	body := []byte{0x04, 0x00, 0x01, 0x00, 0x02}
	body = binary.BigEndian.AppendUint16(body, 0)
	body = binary.BigEndian.AppendUint16(body, uint16(3*cipherSpecs)) //nolint:gosec
	body = binary.BigEndian.AppendUint16(body, 16)
	body = append(body, bytes.Repeat([]byte{0x01, 0x00, 0x80}, cipherSpecs)...)
	body = append(body, make([]byte, 16)...)
	return append(binary.BigEndian.AppendUint16(nil, 0x8000|uint16(len(body))), body...) //nolint:gosec
}

func TestBuildSSLv2ClientHello(t *testing.T) {
	hello, err := probebase.BuildSSLv2ClientHello()

	require.NoError(t, err)
	assert.Equal(t, byte(0x80), hello[0]&0x80)
	assert.Equal(t, len(hello)-2, int(binary.BigEndian.Uint16(hello)&0x7fff))
	assert.Equal(t, []byte{0x01, 0x00, 0x02}, hello[2:5])
}

func TestReadSSLv2ServerHello(t *testing.T) {
	hello, err := probebase.ReadSSLv2ServerHello(bytes.NewReader(sslv2ServerHello(2)))
	require.NoError(t, err)
	assert.Equal(t, 2, hello.CipherSpecs)

	_, err = probebase.ReadSSLv2ServerHello(bytes.NewReader(record(0x15, []byte{0x02, 0x46})))
	assert.ErrorIs(t, err, probebase.ErrHandshakeRejected)

	_, err = probebase.ReadSSLv2ServerHello(bytes.NewReader(nil))
	assert.ErrorIs(t, err, probebase.ErrHandshakeRejected)
}

func TestProbeSSLv2(t *testing.T) {
	host := serve(t, func(conn net.Conn) {
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		_, _ = io.ReadFull(conn, make([]byte, binary.BigEndian.Uint16(header)&0x7fff))
		_, _ = conn.Write(sslv2ServerHello(7))
	})

	hello, err := probebase.ProbeSSLv2(context.Background(), host)
	require.NoError(t, err)
	assert.Equal(t, 7, hello.CipherSpecs)

	_, err = probebase.ProbeSSLv2(context.Background(), tlsServerHost(t, nil))
	assert.ErrorIs(t, err, probebase.ErrHandshakeRejected)
}

func TestRobotPremasterSecrets(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	variants, err := probebase.RobotPremasterSecrets(key.Size())
	require.NoError(t, err)
	require.Len(t, variants, 5)

	for i, variant := range variants {
		require.Len(t, variant, key.Size())
		ciphertext := new(big.Int).Exp(new(big.Int).SetBytes(variant), big.NewInt(int64(key.E)), key.N).FillBytes(make([]byte, key.Size()))
		plaintext, err := rsa.DecryptPKCS1v15(nil, key, ciphertext) //nolint:staticcheck
		switch i {
		case 0:
			require.NoError(t, err)
			assert.Len(t, plaintext, 48)
			assert.Equal(t, []byte{0x03, 0x03}, plaintext[:2])
		case 1, 3:
			assert.Error(t, err)
		case 2:
			require.NoError(t, err)
			assert.Len(t, plaintext, 1)
		case 4:
			require.NoError(t, err)
			assert.Equal(t, []byte{0x02, 0x02}, plaintext[:2])
		}
	}
}

func robotServer(key *rsa.PrivateKey, der []byte, oracle bool) func(net.Conn) {
	return func(conn net.Conn) {
		if _, _, err := readRecord(conn); err != nil {
			return
		}
		flight := append(serverHelloWithExtensions(probebase.VersionTLS12, 0x002f, nil), certificateMessage(der)...)
		flight = append(flight, handshake(0x0e, nil)...)
		_, _ = conn.Write(record(0x16, flight))
		_, payload, err := readRecord(conn)
		if err != nil || len(payload) < 6 {
			return
		}
		m := new(big.Int).Exp(new(big.Int).SetBytes(payload[6:]), key.D, key.N).FillBytes(make([]byte, key.Size()))
		description := byte(20)
		if oracle && (m[0] != 0x00 || m[1] != 0x02) {
			description = 51
		}
		_, _ = conn.Write(record(0x15, []byte{0x02, description}))
	}
}

func TestProbeROBOT(t *testing.T) {
	t.Cleanup(func(previous time.Duration) func() {
		return func() { *probebase.RobotResponseTimeout = previous }
	}(*probebase.RobotResponseTimeout))
	*probebase.RobotResponseTimeout = 200 * time.Millisecond

	key, der := rsaCertificate(t)
	testCases := []struct {
		name     string
		host     string
		expected bool
	}{
		{"padding oracle", serve(t, robotServer(key, der, true)), true},
		{"constant response", serve(t, robotServer(key, der, false)), false},
		{"crypto/tls without rsa key exchange", tlsServerHost(t, nil), false},
		{"crypto/tls with rsa key exchange", tlsServerHost(t, &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA}}), false}, //nolint:gosec
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := probebase.ProbeROBOT(context.Background(), tc.host)

			require.NoError(t, err)
			assert.Equal(t, tc.expected, result.Vulnerable, result.Responses)
		})
	}
}
