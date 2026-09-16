// Package headers_test exercises the checks/headers scanners together
// against a real httptest.Server, driving them through a harnessx.Engine
// exactly as proxyaudit would.
package headers_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	contenttypeoptions "github.com/cerberauth/proxyaudit/proxy/checks/headers/content_type_options"
	cookieflags "github.com/cerberauth/proxyaudit/proxy/checks/headers/cookie_flags"
	"github.com/cerberauth/proxyaudit/proxy/checks/headers/cors"
	"github.com/cerberauth/proxyaudit/proxy/checks/headers/csp"
	frameoptions "github.com/cerberauth/proxyaudit/proxy/checks/headers/frame_options"
	permissionspolicy "github.com/cerberauth/proxyaudit/proxy/checks/headers/permissions_policy"
	referrerpolicy "github.com/cerberauth/proxyaudit/proxy/checks/headers/referrer_policy"
	serverbanner "github.com/cerberauth/proxyaudit/proxy/checks/headers/server_banner"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

const corsTestPath = "/api/account"

func runEngine(t *testing.T, srv *httptest.Server, checks ...harnessx.Check) []harnessx.Observation {
	t.Helper()
	target := scanctx.NewTarget(srv.URL, &scanctx.ScanContext{HTTPClient: srv.Client()})
	all := append([]harnessx.Check{probebase.HTTPFetchCheck}, checks...)
	engine := harnessx.New(harnessx.WithChecks(all...))
	summary, err := engine.Run(context.Background(), target)
	require.NoError(t, err)
	return summary.Observations
}

func TestHeaders_HardenedServer_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=()")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "x", Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	obs := runEngine(t, srv,
		csp.Check, frameoptions.Check, contenttypeoptions.Check,
		referrerpolicy.Check, permissionspolicy.Check, serverbanner.Check, cookieflags.Check,
	)
	assert.Empty(t, obs)
}

func TestHeaders_BareServer_AllFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.Header().Set("X-Powered-By", "PHP/8.1")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "x"}) //nolint:gosec // deliberately insecure fixture for cookieflags.Check
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	obs := runEngine(t, srv,
		csp.Check, frameoptions.Check, contenttypeoptions.Check,
		referrerpolicy.Check, permissionspolicy.Check, serverbanner.Check, cookieflags.Check,
	)

	var titles []string
	for _, o := range obs {
		titles = append(titles, o.Title)
	}
	assert.Contains(t, titles, "Content-Security-Policy header is missing")
	assert.Contains(t, titles, "No clickjacking protection")
	assert.Contains(t, titles, "X-Content-Type-Options header is missing or not set to nosniff")
	assert.Contains(t, titles, "Referrer-Policy header is missing")
	assert.Contains(t, titles, "Permissions-Policy header is missing")
	assert.Contains(t, titles, "Server header discloses software name and version")
	assert.Contains(t, titles, "X-Powered-By header discloses backend technology")
	assert.Contains(t, titles, "Cookie missing security attributes: session")
}

func TestFrameOptions_CSPFrameAncestors_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	obs := runEngine(t, srv, frameoptions.Check)
	assert.Empty(t, obs)
}

func TestCORS_ReflectedOriginWithCredentials_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != corsTestPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	obs := runEngine(t, srv, cors.Check)
	require.NotEmpty(t, obs)

	var titles []string
	for _, o := range obs {
		titles = append(titles, o.Title)
	}
	assert.Contains(t, titles, "Reflected Origin combined with credentialed CORS response: /api/account")
	assert.Contains(t, titles, "CORS accepts the null origin: /api/account")
	assert.Contains(t, titles, "CORS preflight allows credentialed requests from an arbitrary origin: /api/account")
}

func TestCORS_WildcardOriginWithCredentials_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != corsTestPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	obs := runEngine(t, srv, cors.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "Wildcard Access-Control-Allow-Origin combined with Access-Control-Allow-Credentials")
}

func TestCORS_ExcessivePreflightCache_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != corsTestPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Max-Age", "86400")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	obs := runEngine(t, srv, cors.Check)
	require.NotEmpty(t, obs)

	var titles []string
	for _, o := range obs {
		titles = append(titles, o.Title)
	}
	assert.Contains(t, titles, "CORS preflight cache duration exceeds browser ceiling: /api/account")
}

func TestCORS_ScopedToTrustedOrigin_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != corsTestPath {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("Origin") == "https://app.example.com" {
			w.Header().Set("Access-Control-Allow-Origin", "https://app.example.com")
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Set("Vary", "Origin")
		}
		if r.Method == http.MethodOptions {
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	obs := runEngine(t, srv, cors.Check)
	assert.Empty(t, obs)
}
