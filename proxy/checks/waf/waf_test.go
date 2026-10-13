// Package waf_test exercises the checks/waf scanners against a real
// httptest.Server, driving them through a harnessx.Engine exactly as
// proxyaudit would.
package waf_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/proxyaudit/internal/wafstub"
	baselinepayloads "github.com/cerberauth/proxyaudit/proxy/checks/waf/baseline_payloads"
	contenttypeconsistency "github.com/cerberauth/proxyaudit/proxy/checks/waf/content_type_consistency"
	encodingbypass "github.com/cerberauth/proxyaudit/proxy/checks/waf/encoding_bypass"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

func run(t *testing.T, srv *httptest.Server, check harnessx.Check) harnessx.ScanSummary {
	t.Helper()
	target := scanctx.NewTarget(srv.URL, &scanctx.ScanContext{HTTPClient: srv.Client()})
	engine := harnessx.New(harnessx.WithChecks(check))
	summary, err := engine.Run(context.Background(), target)
	require.NoError(t, err)
	return summary
}

func backend() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
}

// naiveWAF inspects only the query string, only once URL-decoded, and
// case-sensitively — the shape of a rule set that never saw an encoding
// evasion or a request body.
func naiveWAF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, _ := url.QueryUnescape(r.URL.RawQuery)
		for _, sig := range []string{"' OR 1=1", "UNION SELECT", "<script", "onerror=", "../", "..\\"} {
			if strings.Contains(decoded, sig) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func TestBaselinePayloads_NoWAF_Flagged(t *testing.T) {
	srv := httptest.NewServer(backend())
	defer srv.Close()

	summary := run(t, srv, baselinepayloads.Check)
	require.Len(t, summary.Observations, 3)
	categories := map[string]bool{}
	for _, o := range summary.Observations {
		categories[o.Metadata["category"]] = true
		assert.Contains(t, o.Description, "no WAF or request filtering appears")
	}
	assert.Equal(t, map[string]bool{"sqli": true, "xss": true, "path_traversal": true}, categories)
}

func TestBaselinePayloads_PartialCoverage_Flagged(t *testing.T) {
	// Blocks XSS and path traversal, but nothing SQL.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		decoded, _ := url.QueryUnescape(r.URL.RawQuery)
		for _, sig := range []string{"<script", "onerror=", "../", "..\\"} {
			if strings.Contains(decoded, sig) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	summary := run(t, srv, baselinepayloads.Check)
	require.Len(t, summary.Observations, 1)
	assert.Equal(t, "sqli", summary.Observations[0].Metadata["category"])
	assert.Contains(t, summary.Observations[0].Description, "coverage of this attack class is incomplete")
}

func TestBaselinePayloads_WAF_NoFindings(t *testing.T) {
	srv := httptest.NewServer(wafstub.Wrap(backend()))
	defer srv.Close()

	assert.Empty(t, run(t, srv, baselinepayloads.Check).Observations)
}

func TestBaselinePayloads_DroppedConnection_CountsAsBlocked(t *testing.T) {
	// nginx's "return 444" closes the connection without a response.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if wafstub.Malicious(r.URL.RawQuery) {
			conn, _, err := w.(http.Hijacker).Hijack()
			require.NoError(t, err)
			_ = conn.Close()
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	assert.Empty(t, run(t, srv, baselinepayloads.Check).Observations)
}

func TestBaselinePayloads_ControlRejected_Skipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	summary := run(t, srv, baselinepayloads.Check)
	assert.Empty(t, summary.Observations)
	require.Len(t, summary.Results, 1)
	assert.True(t, summary.Results[0].Skipped)
}

func TestEncodingBypass_NaiveWAF_Flagged(t *testing.T) {
	srv := httptest.NewServer(naiveWAF(backend()))
	defer srv.Close()

	summary := run(t, srv, encodingbypass.Check)
	require.NotEmpty(t, summary.Observations)

	techniques := map[string]bool{}
	for _, o := range summary.Observations {
		techniques[o.Metadata["technique"]] = true
	}
	assert.True(t, techniques["double URL-encoding"], "got %v", techniques)
	assert.True(t, techniques["case variation"], "got %v", techniques)
}

func TestEncodingBypass_ThoroughWAF_NoFindings(t *testing.T) {
	srv := httptest.NewServer(wafstub.Wrap(backend()))
	defer srv.Close()

	assert.Empty(t, run(t, srv, encodingbypass.Check).Observations)
}

func TestEncodingBypass_NoWAF_NoFindings(t *testing.T) {
	// Nothing is blocked in plain form, so there is nothing to bypass —
	// that is waf.baseline_payloads' finding.
	srv := httptest.NewServer(backend())
	defer srv.Close()

	assert.Empty(t, run(t, srv, encodingbypass.Check).Observations)
}

func TestContentTypeConsistency_QueryOnlyWAF_Flagged(t *testing.T) {
	srv := httptest.NewServer(naiveWAF(backend()))
	defer srv.Close()

	summary := run(t, srv, contenttypeconsistency.Check)
	require.NotEmpty(t, summary.Observations)
	o := summary.Observations[0]
	assert.Contains(t, o.Title, "filtering depends on content type")
	assert.Equal(t, "query string", o.Metadata["blocked"])
	assert.Contains(t, o.Metadata["passed"], "application/json body")
	assert.Contains(t, o.Metadata["passed"], "gzip-encoded form body")
}

func TestContentTypeConsistency_ThoroughWAF_NoFindings(t *testing.T) {
	srv := httptest.NewServer(wafstub.Wrap(backend()))
	defer srv.Close()

	assert.Empty(t, run(t, srv, contenttypeconsistency.Check).Observations)
}

func TestContentTypeConsistency_NoWAF_NoFindings(t *testing.T) {
	srv := httptest.NewServer(backend())
	defer srv.Close()

	assert.Empty(t, run(t, srv, contenttypeconsistency.Check).Observations)
}

// searchOnlyWAF filters only /search?q=, like a rule scoped to one
// endpoint/parameter; everything else, including any other parameter name,
// is served unfiltered.
func searchOnlyWAF() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/search" && wafstub.Malicious(r.URL.Query().Get("q")) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

func runAt(t *testing.T, srv *httptest.Server, path string, check harnessx.Check) harnessx.ScanSummary {
	t.Helper()
	target := scanctx.NewTarget(srv.URL+path, &scanctx.ScanContext{HTTPClient: srv.Client()})
	summary, err := harnessx.New(harnessx.WithChecks(check)).Run(context.Background(), target)
	require.NoError(t, err)
	return summary
}

func TestBaselinePayloads_TargetQueryParameter_Exercised(t *testing.T) {
	srv := httptest.NewServer(searchOnlyWAF())
	defer srv.Close()

	// Payloads go in the target URL's own q parameter, where the filter
	// blocks them.
	assert.Empty(t, runAt(t, srv, "/search?q=test", baselinepayloads.Check).Observations)

	// Without a parameter to reuse, the default one isn't filtered.
	assert.Len(t, runAt(t, srv, "/search", baselinepayloads.Check).Observations, 3)
}

func TestWAFParamFor(t *testing.T) {
	assert.Equal(t, "proxyaudit", probebase.WAFParamFor("https://example.com/"))
	assert.Equal(t, "q", probebase.WAFParamFor("https://example.com/search?q=test&page=2"))
	assert.Equal(t, "my param", probebase.WAFParamFor("https://example.com/?my%20param=1"))
	assert.Equal(t, "flag", probebase.WAFParamFor("https://example.com/?flag"))
	assert.Equal(t, "proxyaudit", probebase.WAFParamFor("https://example.com/?=x"))
}
