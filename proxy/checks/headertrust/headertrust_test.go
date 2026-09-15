// Package headertrust_test exercises the checks/headertrust scanners
// against a real httptest.Server, driving them through a harnessx.Engine
// exactly as proxyaudit would.
package headertrust_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	aclbypass "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/acl_bypass"
	forwardedconsistency "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/forwarded_consistency"
	hostheaderinjection "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/host_header_injection"
	trueclientip "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/true_client_ip"
	vhostconfusion "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/vhost_confusion"
	xforwardedfor "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/x_forwarded_for"
	xforwardedhost "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/x_forwarded_host"
	xrealip "github.com/cerberauth/proxyaudit/proxy/checks/headertrust/x_real_ip"
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

func TestHeaderTrust_NoReflection_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	obs := runEngine(t, srv,
		xforwardedfor.Check, xrealip.Check, trueclientip.Check,
		xforwardedhost.Check, forwardedconsistency.Check,
	)
	assert.Empty(t, obs)
}

func TestXForwardedFor_Reflected_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "your ip: %s", r.Header.Get("X-Forwarded-For")) //nolint:gosec // deliberate reflection fixture for the trust-boundary check under test
	}))
	defer srv.Close()

	obs := runEngine(t, srv, xforwardedfor.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "X-Forwarded-For value reflected")
}

func TestXRealIP_Reflected_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "your ip: %s", r.Header.Get("X-Real-IP")) //nolint:gosec // deliberate reflection fixture for the trust-boundary check under test
	}))
	defer srv.Close()

	obs := runEngine(t, srv, xrealip.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "X-Real-IP value reflected")
}

func TestTrueClientIP_Reflected_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "your ip: %s", r.Header.Get("True-Client-IP")) //nolint:gosec // deliberate reflection fixture for the trust-boundary check under test
	}))
	defer srv.Close()

	obs := runEngine(t, srv, trueclientip.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "True-Client-IP value reflected")
}

func TestXForwardedHost_ReflectedInRedirect_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "https://"+r.Header.Get("X-Forwarded-Host")+"/reset")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	obs := runEngine(t, srv, xforwardedhost.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "X-Forwarded-Host value trusted")
}

func TestForwardedConsistency_BothTrusted_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "forwarded=%s xff=%s", r.Header.Get("Forwarded"), r.Header.Get("X-Forwarded-For")) //nolint:gosec // deliberate reflection fixture for the trust-boundary check under test
	}))
	defer srv.Close()

	obs := runEngine(t, srv, forwardedconsistency.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "Both Forwarded and X-Forwarded-For are trusted")
}

func TestACLBypass_SpoofedLoopback_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/admin" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if r.Header.Get("X-Forwarded-For") != "127.0.0.1" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	obs := runEngine(t, srv, aclbypass.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "IP-based access control bypassed")
}

func TestACLBypass_NoDifference_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	obs := runEngine(t, srv, aclbypass.Check)
	assert.Empty(t, obs)
}

func TestHostHeaderInjection_ReflectedInBody_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/password-reset" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		fmt.Fprintf(w, `{"resetLink": "https://%s/reset?token=abc123"}`, r.Host) //nolint:gosec // deliberate reflection fixture for the trust-boundary check under test
	}))
	defer srv.Close()

	obs := runEngine(t, srv, hostheaderinjection.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "Host header value trusted")
}

func TestHostHeaderInjection_NotReflected_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer srv.Close()

	obs := runEngine(t, srv, hostheaderinjection.Check)
	assert.Empty(t, obs)
}

func TestVHostConfusion_DifferentBodyForCraftedHost_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Host == "internal-admin.local" {
			_, _ = w.Write([]byte(`{"message": "internal admin backend"}`))
			return
		}
		_, _ = w.Write([]byte(`{"message": "public backend"}`))
	}))
	defer srv.Close()

	obs := runEngine(t, srv, vhostconfusion.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "Virtual-host confusion")
	assert.Equal(t, "internal-admin.local", obs[0].Metadata["host"])
}

func TestVHostConfusion_SameBodyForEveryHost_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"message": "public backend"}`))
	}))
	defer srv.Close()

	obs := runEngine(t, srv, vhostconfusion.Check)
	assert.Empty(t, obs)
}

func TestForwardedConsistency_OnlyLegacyTrusted_Flagged(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "xff=%s", r.Header.Get("X-Forwarded-For")) //nolint:gosec // deliberate reflection fixture for the trust-boundary check under test
	}))
	defer srv.Close()

	obs := runEngine(t, srv, forwardedconsistency.Check)
	require.NotEmpty(t, obs)
	assert.Contains(t, obs[0].Title, "inconsistent")
}
