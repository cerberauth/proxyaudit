// Package protocol_test exercises the checks/protocol scanners against an
// HTTP/2-enabled httptest.Server driven through a harnessx.Engine as
// proxyaudit would.
package protocol_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	h2authoritytrust "github.com/cerberauth/proxyaudit/proxy/checks/protocol/h2_authority_trust"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// h2Server starts a TLS server with HTTP/2 enabled serving handler.
func h2Server(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewUnstartedServer(handler)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv
}

func run(t *testing.T, srv *httptest.Server, aggressive bool, check harnessx.Check) harnessx.ScanSummary {
	t.Helper()
	target := scanctx.NewTarget(srv.URL, &scanctx.ScanContext{HTTPClient: srv.Client(), Aggressive: aggressive})
	engine := harnessx.New(harnessx.WithChecks(probebase.HTTPFetchCheck, check))
	summary, err := engine.Run(context.Background(), target)
	require.NoError(t, err)
	return summary
}

// reflectsAuthority echoes the request's :authority (r.Host) into the body
// — a backend/proxy that trusts the client-supplied authority.
func reflectsAuthority() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//nolint:gosec // G705: test reflector deliberately echoes the request authority
		_, _ = w.Write([]byte("host=" + r.Host))
	})
}

func TestH2AuthorityTrust_Reflected_Flagged(t *testing.T) {
	srv := h2Server(t, reflectsAuthority())
	summary := run(t, srv, true, h2authoritytrust.Check)
	require.Len(t, summary.Observations, 1)
	assert.Equal(t, probebase.SpoofedHostMarker, summary.Observations[0].Metadata["authority"])
}

func TestH2AuthorityTrust_NotReflected_NoFindings(t *testing.T) {
	srv := h2Server(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("static body"))
	}))
	assert.Empty(t, run(t, srv, true, h2authoritytrust.Check).Observations)
}

func TestH2AuthorityTrust_NoHTTP2_Skipped(t *testing.T) {
	// Plaintext HTTP/1.1 server: no ALPN h2, the check doesn't apply.
	srv := httptest.NewServer(reflectsAuthority())
	defer srv.Close()
	assert.True(t, skipped(run(t, srv, true, h2authoritytrust.Check), h2authoritytrust.Check.ID))
}

func TestH2AuthorityTrust_NotAggressive_Skipped(t *testing.T) {
	srv := h2Server(t, reflectsAuthority())
	assert.True(t, skipped(run(t, srv, false, h2authoritytrust.Check), h2authoritytrust.Check.ID))
}

func skipped(summary harnessx.ScanSummary, id harnessx.CheckID) bool {
	for _, r := range summary.Results {
		if r.CheckID == id {
			return r.Skipped
		}
	}
	return false
}
