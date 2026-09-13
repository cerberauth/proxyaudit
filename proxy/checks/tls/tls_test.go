// Package tls_test exercises the checks/tls scanners together against a
// real httptest.Server (TLS or plain HTTP as each test needs), driving them
// through a harnessx.Engine exactly as proxyaudit would, so no live network
// access is required.
package tls_test

import (
	"context"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/proxyaudit/proxy/checks/tls/certificate"
	cipherstrength "github.com/cerberauth/proxyaudit/proxy/checks/tls/cipher_strength"
	"github.com/cerberauth/proxyaudit/proxy/checks/tls/hsts"
	httpsredirect "github.com/cerberauth/proxyaudit/proxy/checks/tls/https_redirect"
	protocolversion "github.com/cerberauth/proxyaudit/proxy/checks/tls/protocol_version"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

func runEngine(t *testing.T, target harnessx.Target, checks ...harnessx.Check) []harnessx.Observation {
	t.Helper()
	all := append([]harnessx.Check{probebase.TLSInfoCheck, probebase.HTTPFetchCheck}, checks...)
	engine := harnessx.New(harnessx.WithChecks(all...))
	summary, err := engine.Run(context.Background(), target)
	require.NoError(t, err)
	return summary.Observations
}

func newTLSTarget(t *testing.T, srv *httptest.Server) harnessx.Target {
	t.Helper()
	cert, err := x509.ParseCertificate(srv.Certificate().Raw)
	require.NoError(t, err)
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return scanctx.NewTarget(srv.URL, &scanctx.ScanContext{HTTPClient: srv.Client(), RootCAs: pool})
}

func TestCertificate_HardenedServer_NoChainOrExpiryFindings(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// httptest's cert is trusted (via RootCAs override) and freshly
	// generated per test run, so only the always-true-in-this-harness OCSP
	// stapling finding is expected — httptest never staples OCSP.
	obs := runEngine(t, newTLSTarget(t, srv), certificate.Check)
	var titles []string
	for _, o := range obs {
		titles = append(titles, o.Title)
	}
	assert.NotContains(t, titles, "Certificate chain does not verify")
	assert.NotContains(t, titles, "Certificate has expired")
	assert.NotContains(t, titles, "Certificate expires soon")
}

func TestCertificate_UntrustedChain_Flagged(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// No RootCAs override -> httptest's self-signed cert won't verify
	// against the system trust store.
	target := scanctx.NewTarget(srv.URL, &scanctx.ScanContext{HTTPClient: srv.Client()})

	obs := runEngine(t, target, certificate.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "chain does not verify")
}

func TestCipherStrength_ModernServer_HasForwardSecrecy(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	obs := runEngine(t, newTLSTarget(t, srv), cipherstrength.Check)
	for _, o := range obs {
		assert.NotContains(t, o.Title, "forward secrecy")
	}
}

func TestProtocolVersion_ModernServer_NoDeprecatedVersions(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	obs := runEngine(t, newTLSTarget(t, srv), protocolversion.Check)
	assert.Empty(t, obs)
}

func TestHTTPSRedirect_NoRedirect_Flagged(t *testing.T) {
	// httptest.NewServer is plain HTTP; https_redirect derives the
	// plain-HTTP probe URL from the target URL's host:port, so pointing
	// the (https-labelled) target at a plain-HTTP server simulates "no
	// redirect happens".
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	httpsURL := "https" + srv.URL[len("http"):]
	target := scanctx.NewTarget(httpsURL, &scanctx.ScanContext{HTTPClient: srv.Client()})

	engine := harnessx.New(harnessx.WithChecks(httpsredirect.Check))
	summary, err := engine.Run(context.Background(), target)
	require.NoError(t, err)
	require.NotEmpty(t, summary.Observations)
	assert.Contains(t, summary.Observations[0].Title, "not redirected to HTTPS")
}

func TestHTTPSRedirect_RedirectsToHTTPS_NoFindings(t *testing.T) {
	var httpsHost string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://"+httpsHost+r.URL.Path, http.StatusMovedPermanently) //nolint:gosec // fixed test-server address, not attacker input
	}))
	defer srv.Close()
	httpsHost = srv.Listener.Addr().String()

	httpsURL := "https" + srv.URL[len("http"):]
	target := scanctx.NewTarget(httpsURL, &scanctx.ScanContext{HTTPClient: srv.Client()})

	engine := harnessx.New(harnessx.WithChecks(httpsredirect.Check))
	summary, err := engine.Run(context.Background(), target)
	require.NoError(t, err)
	assert.Empty(t, summary.Observations)
}

func TestHSTS_MissingHeader_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	target := scanctx.NewTarget(srv.URL, &scanctx.ScanContext{HTTPClient: srv.Client()})
	obs := runEngine(t, target, hsts.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "missing")
}

func TestHSTS_SaneHeader_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	target := scanctx.NewTarget(srv.URL, &scanctx.ScanContext{HTTPClient: srv.Client()})
	obs := runEngine(t, target, hsts.Check)
	assert.Empty(t, obs)
}

func TestHSTS_WeakMaxAge_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Strict-Transport-Security", "max-age=60")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	target := scanctx.NewTarget(srv.URL, &scanctx.ScanContext{HTTPClient: srv.Client()})
	obs := runEngine(t, target, hsts.Check)
	var titles []string
	for _, o := range obs {
		titles = append(titles, o.Title)
	}
	assert.Contains(t, titles, "Strict-Transport-Security max-age is too low")
	assert.Contains(t, titles, "Strict-Transport-Security missing includeSubDomains")
	assert.Contains(t, titles, "Strict-Transport-Security missing preload")
}
