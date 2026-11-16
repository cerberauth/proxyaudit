// Package caching_test exercises the checks/caching scanners against a
// real httptest.Server, driving them through a harnessx.Engine exactly as
// proxyaudit would.
package caching_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/proxyaudit/proxy/checks/caching"
	authenticatedcaching "github.com/cerberauth/proxyaudit/proxy/checks/caching/authenticated_caching"
	cachedeception "github.com/cerberauth/proxyaudit/proxy/checks/caching/cache_deception"
	cachepoisoning "github.com/cerberauth/proxyaudit/proxy/checks/caching/cache_poisoning"
	varyconsistency "github.com/cerberauth/proxyaudit/proxy/checks/caching/vary_consistency"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

func runEngine(t *testing.T, srv *httptest.Server, aggressive bool, def checkdef.CheckDef) []harnessx.Observation {
	t.Helper()
	return runEngineAtURL(t, srv.URL, srv.Client(), aggressive, def)
}

func runEngineAtURL(t *testing.T, url string, client *http.Client, aggressive bool, def checkdef.CheckDef) []harnessx.Observation {
	t.Helper()
	target := scanctx.NewTarget(url, &scanctx.ScanContext{HTTPClient: client, Aggressive: aggressive})
	engine := harnessx.New(harnessx.WithChecks(append([]harnessx.Check{probebase.HTTPFetchCheck}, caching.Checks()...)...))
	summary, err := engine.Run(context.Background(), target, harnessx.WithOnly(harnessx.CheckID(def.ID)))
	require.NoError(t, err)
	for _, r := range summary.Results {
		require.NoError(t, r.Err, "%s", r.CheckID)
	}
	var obs []harnessx.Observation
	for _, o := range summary.Observations {
		if o.CheckID == harnessx.CheckID(def.ID) {
			obs = append(obs, o)
		}
	}
	return obs
}

func TestAuthenticatedCaching_NoOptIn_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			w.Header().Set("Cache-Control", "max-age=3600")
			_, _ = w.Write([]byte("account info secret@example.com"))
			return
		}
		_, _ = w.Write([]byte("public info"))
	}))
	defer srv.Close()

	obs := runEngine(t, srv, false, authenticatedcaching.Def)
	require.Len(t, obs, 1)
	assert.Equal(t, "Authenticated response marked cacheable", obs[0].Title)
	assert.Contains(t, obs[0].Description, "email address")
}

func TestAuthenticatedCaching_Private_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			w.Header().Set("Cache-Control", "private, max-age=3600")
			_, _ = w.Write([]byte("account info"))
			return
		}
		_, _ = w.Write([]byte("public info"))
	}))
	defer srv.Close()

	obs := runEngine(t, srv, false, authenticatedcaching.Def)
	assert.Empty(t, obs)
}

func TestVaryConsistency_UndeclaredLanguageDimension_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Language") == "fr-FR" {
			_, _ = w.Write([]byte("bonjour"))
			return
		}
		_, _ = w.Write([]byte("hello"))
	}))
	defer srv.Close()

	obs := runEngine(t, srv, false, varyconsistency.Def)
	require.Len(t, obs, 1)
	assert.Contains(t, obs[0].Title, "accept-language")
}

func TestVaryConsistency_NoVariance_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("static content"))
	}))
	defer srv.Close()

	obs := runEngine(t, srv, false, varyconsistency.Def)
	assert.Empty(t, obs)
}

// poisonableHandler models a reverse proxy / origin that remembers the last
// X-Forwarded-Host it saw and reflects it into every subsequent response
// regardless of whether that later request carries the header — the
// unkeyed-input pattern that lets one poisoned request affect every
// following visitor.
func poisonableHandler() http.HandlerFunc {
	var lastHost string
	return func(w http.ResponseWriter, r *http.Request) {
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			lastHost = xfh
		}
		if lastHost != "" {
			fmt.Fprintf(w, "host=%s", lastHost) //nolint:gosec // deliberate reflection fixture for the poisoning check under test
			return
		}
		_, _ = w.Write([]byte("normal response"))
	}
}

func TestCachePoisoning_Aggressive_UnkeyedHeaderPersists_Flagged(t *testing.T) {
	srv := httptest.NewServer(poisonableHandler())
	defer srv.Close()

	obs := runEngine(t, srv, true, cachepoisoning.Def)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "Unkeyed header injection via X-Forwarded-Host")
}

func TestCachePoisoning_NotAggressive_Skipped(t *testing.T) {
	srv := httptest.NewServer(poisonableHandler())
	defer srv.Close()

	obs := runEngine(t, srv, false, cachepoisoning.Def)
	assert.Empty(t, obs)
}

func TestCachePoisoning_StatelessReflection_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if xfh := r.Header.Get("X-Forwarded-Host"); xfh != "" {
			fmt.Fprintf(w, "host=%s", xfh) //nolint:gosec // deliberate reflection fixture, not persisted
			return
		}
		_, _ = w.Write([]byte("normal response"))
	}))
	defer srv.Close()

	obs := runEngine(t, srv, true, cachepoisoning.Def)
	assert.Empty(t, obs)
}

func deceptionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account", "/account;.css":
			w.Header().Set("Cache-Control", "public, max-age=60")
			_, _ = w.Write([]byte("secret account data"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestCacheDeception_Aggressive_StaticExtensionServesSameContent_Flagged(t *testing.T) {
	srv := httptest.NewServer(deceptionHandler())
	defer srv.Close()

	obs := runEngineAtURL(t, srv.URL+"/account", srv.Client(), true, cachedeception.Def)
	require.Len(t, obs, 1)
	assert.Equal(t, "Cache deception via path confusion", obs[0].Title)
	assert.Contains(t, obs[0].Evidence, "/account;.css")
}

func TestCacheDeception_NotAggressive_Skipped(t *testing.T) {
	srv := httptest.NewServer(deceptionHandler())
	defer srv.Close()

	obs := runEngineAtURL(t, srv.URL+"/account", srv.Client(), false, cachedeception.Def)
	assert.Empty(t, obs)
}

func TestCacheDeception_NoStoreOnDeceptivePath_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/account", "/account.js":
			w.Header().Set("Cache-Control", "no-store")
			_, _ = w.Write([]byte("secret account data"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	obs := runEngineAtURL(t, srv.URL+"/account", srv.Client(), true, cachedeception.Def)
	assert.Empty(t, obs)
}
