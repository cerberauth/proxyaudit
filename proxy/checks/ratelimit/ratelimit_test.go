// Package ratelimit_test exercises the checks/ratelimit scanners against
// httptest servers modelling different throttling behaviours, driven
// through a harnessx.Engine as proxyaudit would.
package ratelimit_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	missingthrottling "github.com/cerberauth/proxyaudit/proxy/checks/ratelimit/missing_throttling"
	oversizedheader "github.com/cerberauth/proxyaudit/proxy/checks/ratelimit/oversized_header"
	spoofedipbypass "github.com/cerberauth/proxyaudit/proxy/checks/ratelimit/spoofed_ip_bypass"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

const limit = 8

func run(t *testing.T, srv *httptest.Server, aggressive bool, check harnessx.Check) harnessx.ScanSummary {
	t.Helper()
	target := scanctx.NewTarget(srv.URL, &scanctx.ScanContext{HTTPClient: srv.Client(), Aggressive: aggressive})
	engine := harnessx.New(harnessx.WithChecks(probebase.HTTPFetchCheck, check))
	summary, err := engine.Run(context.Background(), target)
	require.NoError(t, err)
	return summary
}

func noLimit() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

// perClientLimit throttles after `limit` requests sharing the same key,
// where the key is the X-Forwarded-For header if present, else the peer —
// the misconfiguration the bypass check looks for.
func perClientLimit() http.Handler {
	var mu sync.Mutex
	seen := map[string]int{}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-Forwarded-For")
		if key == "" {
			key = "peer"
		}
		mu.Lock()
		seen[key]++
		over := seen[key] > limit
		mu.Unlock()
		if over {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

// globalLimit throttles after `limit` total requests regardless of any
// client-supplied header — correct keying, nothing to bypass.
func globalLimit() http.Handler {
	var mu sync.Mutex
	var n int
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		n++
		over := n > limit
		mu.Unlock()
		if over {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

func rejectBigHeader() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if len(r.Header.Get("X-Proxyaudit-Pad")) > 8192 {
			w.WriteHeader(http.StatusRequestHeaderFieldsTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
}

func TestMissingThrottling_NoLimit_Flagged(t *testing.T) {
	srv := httptest.NewServer(noLimit())
	defer srv.Close()
	assert.Len(t, run(t, srv, true, missingthrottling.Check).Observations, 1)
}

func TestMissingThrottling_Throttled_NoFindings(t *testing.T) {
	srv := httptest.NewServer(globalLimit())
	defer srv.Close()
	assert.Empty(t, run(t, srv, true, missingthrottling.Check).Observations)
}

func TestMissingThrottling_NotAggressive_Skipped(t *testing.T) {
	srv := httptest.NewServer(noLimit())
	defer srv.Close()
	assert.True(t, skipped(run(t, srv, false, missingthrottling.Check), missingthrottling.Check.ID))
}

func TestSpoofedIPBypass_PerClientKey_Flagged(t *testing.T) {
	srv := httptest.NewServer(perClientLimit())
	defer srv.Close()
	summary := run(t, srv, true, spoofedipbypass.Check)
	require.Len(t, summary.Observations, 1)
	assert.Equal(t, "X-Forwarded-For", summary.Observations[0].Metadata["header"])
}

func TestSpoofedIPBypass_GlobalKey_NoFindings(t *testing.T) {
	srv := httptest.NewServer(globalLimit())
	defer srv.Close()
	assert.Empty(t, run(t, srv, true, spoofedipbypass.Check).Observations)
}

func TestSpoofedIPBypass_NoThrottling_Skipped(t *testing.T) {
	srv := httptest.NewServer(noLimit())
	defer srv.Close()
	assert.True(t, skipped(run(t, srv, true, spoofedipbypass.Check), spoofedipbypass.Check.ID))
}

func TestOversizedHeader_Accepted_Flagged(t *testing.T) {
	srv := httptest.NewServer(noLimit())
	defer srv.Close()
	assert.Len(t, run(t, srv, true, oversizedheader.Check).Observations, 1)
}

func TestOversizedHeader_Rejected_NoFindings(t *testing.T) {
	srv := httptest.NewServer(rejectBigHeader())
	defer srv.Close()
	assert.Empty(t, run(t, srv, true, oversizedheader.Check).Observations)
}

func skipped(summary harnessx.ScanSummary, id harnessx.CheckID) bool {
	for _, r := range summary.Results {
		if r.CheckID == id {
			return r.Skipped
		}
	}
	return false
}
