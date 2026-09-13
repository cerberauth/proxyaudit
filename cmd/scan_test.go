package cmd_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/proxyaudit/cmd"
)

func runScan(t *testing.T, args ...string) error {
	t.Helper()
	root := cmd.NewRootCmd("test", "none", "unknown")
	root.SetArgs(append([]string{"scan", "--sqa-opt-out", "--quiet"}, args...))
	return root.Execute()
}

func TestScan_HardenedServer_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "geolocation=()")
		h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	err := runScan(t, srv.URL)
	assert.NoError(t, err)
}

func TestScan_BareServer_FindingsPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.18.0")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := runScan(t, srv.URL)
	require.Error(t, err)
	assert.Empty(t, err.Error()) // errFindingsPresent carries no message

	var runtimeErr *cmd.RuntimeError
	assert.False(t, errors.As(err, &runtimeErr), "findings-present must not be classified as a runtime error")
}

func TestScan_UnreachableTarget_RuntimeError(t *testing.T) {
	err := runScan(t, "https://not-a-real-host-proxyaudit-test.invalid")
	require.Error(t, err)

	var runtimeErr *cmd.RuntimeError
	require.ErrorAs(t, err, &runtimeErr)
}

func TestScan_UnknownEngine_UsageError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	err := runScan(t, srv.URL, "--engine", "made-up-engine")
	require.Error(t, err)

	var runtimeErr *cmd.RuntimeError
	assert.False(t, errors.As(err, &runtimeErr))
}
