// Package disclosure_test exercises the checks/disclosure scanners against
// a real httptest.Server, driving them through a harnessx.Engine exactly as
// proxyaudit would.
package disclosure_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	configexposure "github.com/cerberauth/proxyaudit/proxy/checks/disclosure/config_exposure"
	directorylisting "github.com/cerberauth/proxyaudit/proxy/checks/disclosure/directory_listing"
	exposedmanagement "github.com/cerberauth/proxyaudit/proxy/checks/disclosure/exposed_management"
	verboseerrors "github.com/cerberauth/proxyaudit/proxy/checks/disclosure/verbose_errors"
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

func TestDisclosure_HardenedServer_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer srv.Close()

	obs := runEngine(t, srv,
		exposedmanagement.Check, directorylisting.Check, configexposure.Check, verboseerrors.Check,
	)
	assert.Empty(t, obs)
}

func TestExposedManagement_TraefikAPI_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/rawdata" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"routers": {}, "services": {}}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	obs := runEngine(t, srv, exposedmanagement.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "Traefik API reachable")
}

func TestDirectoryListing_Enabled_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			_, _ = w.Write([]byte("<html><body><h1>Index of /</h1><a href=\"../\">Parent Directory</a></body></html>"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	obs := runEngine(t, srv, directorylisting.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "Directory listing enabled")
}

func TestConfigExposure_EnvFile_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.env" {
			_, _ = w.Write([]byte("DATABASE_URL=postgres://user:pass@db/app\nAPI_KEY=abc123"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	obs := runEngine(t, srv, configexposure.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "Environment file")
}

func TestVerboseErrors_StackTraceLeaked_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("Traceback (most recent call last):\n  File \"/home/app/server.py\", line 42"))
	}))
	defer srv.Close()

	obs := runEngine(t, srv, verboseerrors.Check)
	require.NotEmpty(t, obs)
}
