// Package ssrf_test exercises the checks/ssrf scanners against a real
// httptest.Server driven through a harnessx.Engine, exactly as proxyaudit
// would. The test servers stand in for the proxy: an "open proxy" acts on
// the absolute-form request-target's authority, a "reverse proxy" ignores
// it and always serves its backend.
package ssrf_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	internaltargetaccess "github.com/cerberauth/proxyaudit/proxy/checks/ssrf/internal_target_access"
	openforwardproxy "github.com/cerberauth/proxyaudit/proxy/checks/ssrf/open_forward_proxy"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

func run(t *testing.T, srv *httptest.Server, aggressive bool, check harnessx.Check) harnessx.ScanSummary {
	t.Helper()
	target := scanctx.NewTarget(srv.URL, &scanctx.ScanContext{HTTPClient: srv.Client(), Aggressive: aggressive})
	engine := harnessx.New(harnessx.WithChecks(probebase.HTTPFetchCheck, check))
	summary, err := engine.Run(context.Background(), target)
	require.NoError(t, err)
	return summary
}

var internalHosts = map[string]bool{
	"127.0.0.1": true, "localhost": true, "::1": true,
	"169.254.169.254": true, "metadata.google.internal": true,
	"10.0.0.1": true, "192.168.0.1": true,
}

// openProxy acts on the absolute-form request-target authority: it fetches
// example.com and internal hosts, and gateway-errors on anything it can't
// resolve. Origin-form requests get the backend page.
func openProxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.RequestURI, "http://") {
			_, _ = w.Write([]byte("BACKEND HOME PAGE"))
			return
		}
		switch host := r.URL.Hostname(); {
		case host == "example.com":
			_, _ = w.Write([]byte("<h1>Example Domain</h1><p>illustrative examples</p>"))
		case internalHosts[host]:
			_, _ = w.Write([]byte("INTERNAL-SERVICE " + host))
		default: // unresolvable / unreachable
			w.WriteHeader(http.StatusBadGateway)
		}
	})
}

// reverseProxy ignores the request-target authority and always serves its
// backend — a correctly scoped proxy.
func reverseProxy() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("BACKEND HOME PAGE"))
	})
}

func TestOpenForwardProxy_OpenProxy_Flagged(t *testing.T) {
	srv := httptest.NewServer(openProxy())
	defer srv.Close()

	summary := run(t, srv, true, openforwardproxy.Check)
	require.Len(t, summary.Observations, 1)
	assert.Equal(t, "example.com", summary.Observations[0].Metadata["forwarded_host"])
}

func TestOpenForwardProxy_ReverseProxy_NoFindings(t *testing.T) {
	srv := httptest.NewServer(reverseProxy())
	defer srv.Close()

	assert.Empty(t, run(t, srv, true, openforwardproxy.Check).Observations)
}

func TestOpenForwardProxy_NotAggressive_Skipped(t *testing.T) {
	srv := httptest.NewServer(openProxy())
	defer srv.Close()

	summary := run(t, srv, false, openforwardproxy.Check)
	assert.Empty(t, summary.Observations)
	assert.True(t, skipped(summary, openforwardproxy.Check.ID))
}

func TestInternalTargetAccess_OpenProxy_Flagged(t *testing.T) {
	srv := httptest.NewServer(openProxy())
	defer srv.Close()

	summary := run(t, srv, true, internaltargetaccess.Check)
	require.NotEmpty(t, summary.Observations)
	hosts := map[string]bool{}
	for _, o := range summary.Observations {
		hosts[o.Metadata["host"]] = true
	}
	assert.True(t, hosts["169.254.169.254"], "metadata endpoint should be flagged: %v", hosts)
	assert.True(t, hosts["127.0.0.1"], "loopback should be flagged: %v", hosts)
}

func TestInternalTargetAccess_ReverseProxy_Skipped(t *testing.T) {
	srv := httptest.NewServer(reverseProxy())
	defer srv.Close()

	summary := run(t, srv, true, internaltargetaccess.Check)
	assert.Empty(t, summary.Observations)
	assert.True(t, skipped(summary, internaltargetaccess.Check.ID))
}

func TestInternalTargetAccess_NotAggressive_Skipped(t *testing.T) {
	srv := httptest.NewServer(openProxy())
	defer srv.Close()

	assert.True(t, skipped(run(t, srv, false, internaltargetaccess.Check), internaltargetaccess.Check.ID))
}

func skipped(summary harnessx.ScanSummary, id harnessx.CheckID) bool {
	for _, r := range summary.Results {
		if r.CheckID == id {
			return r.Skipped
		}
	}
	return false
}
