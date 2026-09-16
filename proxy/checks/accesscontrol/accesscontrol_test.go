// Package accesscontrol_test exercises the checks/accesscontrol scanners
// against a real httptest.Server, driving them through a harnessx.Engine
// exactly as proxyaudit would.
package accesscontrol_test

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

	methodbypass "github.com/cerberauth/proxyaudit/proxy/checks/accesscontrol/method_bypass"
	pathbypass "github.com/cerberauth/proxyaudit/proxy/checks/accesscontrol/path_bypass"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

func runEngine(t *testing.T, srv *httptest.Server, checks ...harnessx.Check) []harnessx.Observation {
	t.Helper()
	target := scanctx.NewTarget(srv.URL, &scanctx.ScanContext{HTTPClient: srv.Client()})
	engine := harnessx.New(harnessx.WithChecks(checks...))
	summary, err := engine.Run(context.Background(), target)
	require.NoError(t, err)
	return summary.Observations
}

// naivePrefixACL blocks GET /admin via a raw, case-sensitive prefix match on
// the undecoded path — the same naive check the proxy-path-bypass challenge
// models — so any case/encoding/traversal variant that still targets
// /admin, or any other verb, reaches the handler unblocked.
func naivePrefixACL(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/admin") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// normalizedACL decodes and normalizes the path (and gates every verb)
// before the same prefix check, closing both the path-normalization and
// method-based bypasses.
func normalizedACL(w http.ResponseWriter, r *http.Request) {
	decoded, err := url.PathUnescape(r.URL.Path)
	if err != nil {
		decoded = r.URL.Path
	}
	cleaned := "/" + strings.Trim(strings.ToLower(decoded), "/")
	for strings.Contains(cleaned, "//") {
		cleaned = strings.ReplaceAll(cleaned, "//", "/")
	}
	if strings.HasPrefix(cleaned, "/admin") {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusOK)
}

func TestPathBypass_NaivePrefixCheck_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(naivePrefixACL))
	defer srv.Close()

	obs := runEngine(t, srv, pathbypass.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "Access control bypassed via path normalization")
	assert.Equal(t, "/admin", obs[0].Metadata["path"])
}

func TestPathBypass_NormalizedCheck_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(normalizedACL))
	defer srv.Close()

	obs := runEngine(t, srv, pathbypass.Check)
	assert.Empty(t, obs)
}

func TestMethodBypass_GETOnlyCheck_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(naivePrefixACL))
	defer srv.Close()

	obs := runEngine(t, srv, methodbypass.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "Access control bypassed via HTTP method")
	assert.Equal(t, "/admin", obs[0].Metadata["path"])
}

func TestMethodBypass_EveryVerbGated_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(normalizedACL))
	defer srv.Close()

	obs := runEngine(t, srv, methodbypass.Check)
	assert.Empty(t, obs)
}

func TestAccessControl_AlwaysDenied_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	obs := runEngine(t, srv, pathbypass.Check, methodbypass.Check)
	assert.Empty(t, obs)
}
