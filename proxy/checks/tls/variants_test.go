package tls_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/proxyaudit/proxy/checks/tls/certificate"
	cipherstrength "github.com/cerberauth/proxyaudit/proxy/checks/tls/cipher_strength"
	"github.com/cerberauth/proxyaudit/proxy/checks/tls/drown"
	"github.com/cerberauth/proxyaudit/proxy/checks/tls/heartbleed"
	protocolversion "github.com/cerberauth/proxyaudit/proxy/checks/tls/protocol_version"
	"github.com/cerberauth/proxyaudit/proxy/checks/tls/robot"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

const localIP = "127.0.0.1"

type issuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newCA(t *testing.T) issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-48 * time.Hour),
		NotAfter:              time.Now().Add(48 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return issuer{cert: cert, key: key}
}

func newLeaf(t *testing.T, ca *issuer, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: localIP},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		IPAddresses:  []net.IP{net.ParseIP(localIP)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	parent, signer := template, key
	if ca != nil {
		parent, signer = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, signer)
	require.NoError(t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func newServer(t *testing.T, config *tls.Config) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.TLS = config
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func codes(observations []harnessx.Observation) []string {
	var result []string
	for _, o := range observations {
		result = append(result, o.Metadata["code"])
	}
	return result
}

func TestCertificate_Variants(t *testing.T) {
	ca := newCA(t)
	other := newCA(t)
	now := time.Now()
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)

	testCases := []struct {
		name     string
		leaf     tls.Certificate
		host     string
		expected []string
		absent   []string
	}{
		{"valid", newLeaf(t, &ca, now.Add(-time.Hour), now.Add(90*24*time.Hour)), localIP, nil, []string{certificate.CodeUntrustedChain, certificate.CodeSelfSigned, certificate.CodeHostnameMismatch, certificate.CodeExpired, certificate.CodeExpiresSoon}},
		{"expired", newLeaf(t, &ca, now.Add(-48*time.Hour), now.Add(-time.Hour)), localIP, []string{certificate.CodeExpired}, []string{certificate.CodeUntrustedChain, certificate.CodeHostnameMismatch}},
		{"expires soon", newLeaf(t, &ca, now.Add(-time.Hour), now.Add(24*time.Hour)), localIP, []string{certificate.CodeExpiresSoon}, []string{certificate.CodeExpired}},
		{"self-signed", newLeaf(t, nil, now.Add(-time.Hour), now.Add(90*24*time.Hour)), localIP, []string{certificate.CodeSelfSigned}, []string{certificate.CodeUntrustedChain}},
		{"untrusted issuer", newLeaf(t, &other, now.Add(-time.Hour), now.Add(90*24*time.Hour)), localIP, []string{certificate.CodeUntrustedChain}, []string{certificate.CodeSelfSigned}},
		{"wrong host", newLeaf(t, &ca, now.Add(-time.Hour), now.Add(90*24*time.Hour)), "localhost", []string{certificate.CodeHostnameMismatch}, []string{certificate.CodeUntrustedChain, certificate.CodeExpired}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := newServer(t, &tls.Config{Certificates: []tls.Certificate{tc.leaf}})
			url := strings.Replace(srv.URL, localIP, tc.host, 1)

			got := codes(runEngine(t, scanctx.NewTarget(url, &scanctx.ScanContext{RootCAs: roots}), certificate.Check))

			for _, code := range tc.expected {
				assert.Contains(t, got, code)
			}
			for _, code := range tc.absent {
				assert.NotContains(t, got, code)
			}
		})
	}
}

func TestProtocolVersion_MinimumVersion(t *testing.T) {
	testCases := []struct {
		name       string
		minVersion uint16
		versions   string
	}{
		{"TLS 1.0 allowed", tls.VersionTLS10, "TLS 1.0, TLS 1.1"},
		{"TLS 1.1 allowed", tls.VersionTLS11, "TLS 1.1"},
		{"TLS 1.2 minimum", tls.VersionTLS12, ""},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
			srv.TLS = &tls.Config{MinVersion: tc.minVersion}
			srv.StartTLS()
			t.Cleanup(srv.Close)

			obs := runEngine(t, newTLSTarget(t, srv), protocolversion.Check)

			if tc.versions == "" {
				assert.Empty(t, obs)
				return
			}
			require.Len(t, obs, 1)
			assert.Equal(t, protocolversion.CodeLegacyEnabled, obs[0].Metadata["code"])
			assert.Equal(t, tc.versions, obs[0].Metadata["versions"])
		})
	}
}

func skipReasons(t *testing.T, target harnessx.Target) map[harnessx.CheckID]string {
	t.Helper()
	engine := harnessx.New(harnessx.WithChecks(probebase.TLSInfoCheck, certificate.Check, protocolversion.Check, cipherstrength.Check, heartbleed.Check, drown.Check, robot.Check))
	summary, err := engine.Run(context.Background(), target)
	require.NoError(t, err)
	reasons := map[harnessx.CheckID]string{}
	for _, r := range summary.Results {
		if r.Skipped {
			reasons[r.CheckID] = r.SkipReason
		}
	}
	return reasons
}

func TestTLSChecks_SkipWithReason(t *testing.T) {
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(plain.Close)
	closed, err := net.Listen("tcp", localIP+":0")
	require.NoError(t, err)
	closedAddr := closed.Addr().String()
	require.NoError(t, closed.Close())

	testCases := []struct {
		name   string
		url    string
		reason string
	}{
		{"plain HTTP URL", plain.URL, "target URL uses plain HTTP, no TLS to inspect"},
		{"plain HTTP port", strings.Replace(plain.URL, "http://", "https://", 1), "target port does not speak TLS (plain HTTP)"},
		{"closed port", "https://" + closedAddr, "target port is closed or unreachable"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reasons := skipReasons(t, scanctx.NewTarget(tc.url, nil))

			for _, id := range []harnessx.CheckID{certificate.Check.ID, protocolversion.Check.ID, cipherstrength.Check.ID, heartbleed.Check.ID, drown.Check.ID, robot.Check.ID} {
				assert.Equal(t, tc.reason, reasons[id], id)
			}
		})
	}
}

func TestKnownCVEs_ModernServer_NoFindings(t *testing.T) {
	testCases := []struct {
		name   string
		config *tls.Config
	}{
		{"default", nil},
		{"rsa key exchange", &tls.Config{MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256, tls.TLS_RSA_WITH_AES_128_CBC_SHA}}}, //nolint:gosec
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
			srv.TLS = tc.config
			srv.StartTLS()
			t.Cleanup(srv.Close)

			engine := harnessx.New(harnessx.WithChecks(probebase.TLSInfoCheck, heartbleed.Check, drown.Check, robot.Check))
			summary, err := engine.Run(context.Background(), newTLSTarget(t, srv))

			require.NoError(t, err)
			assert.Empty(t, summary.Observations)
			for _, result := range summary.Results {
				assert.False(t, result.Skipped, result.CheckID)
			}
		})
	}
}
