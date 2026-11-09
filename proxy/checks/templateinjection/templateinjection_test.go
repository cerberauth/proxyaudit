// Package templateinjection_test exercises the templateinjection checks
// against a real httptest.Server driven through a harnessx.Engine, exactly
// as proxyaudit would.
package templateinjection_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	headerssti "github.com/cerberauth/proxyaudit/proxy/checks/templateinjection/header_ssti"
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

// evalBrace renders the Jinja2/Twig-style {{a*b}} expression in the given
// header, echoing the product — the behaviour of a proxy that templates a
// reflected header. Any other value is echoed verbatim.
func evalBrace(header string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v := r.Header.Get(header)
		if strings.HasPrefix(v, "{{") && strings.HasSuffix(v, "}}") && strings.Contains(v, "*") {
			expr := strings.TrimSuffix(strings.TrimPrefix(v, "{{"), "}}")
			parts := strings.SplitN(expr, "*", 2)
			a, err1 := strconv.Atoi(strings.TrimSpace(parts[0]))
			b, err2 := strconv.Atoi(strings.TrimSpace(parts[1]))
			if err1 == nil && err2 == nil {
				_, _ = w.Write([]byte("echo: " + strconv.Itoa(a*b)))
				return
			}
		}
		_, _ = w.Write([]byte("echo: " + v))
	})
}

func TestHeaderSSTI_TemplatingProxy_Flagged(t *testing.T) {
	srv := httptest.NewServer(evalBrace("Referer"))
	defer srv.Close()

	summary := run(t, srv, true, headerssti.Check)
	require.NotEmpty(t, summary.Observations)
	o := summary.Observations[0]
	assert.Equal(t, "Referer", o.Metadata["header"])
	assert.Equal(t, "{{7919*8039}}", o.Metadata["expression"])
	assert.Contains(t, o.Description, "63660841")
}

func TestHeaderSSTI_PlainEcho_NoFindings(t *testing.T) {
	// Reflects the header verbatim without evaluating it: the raw
	// expression comes back, never the product.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("referer: " + r.Header.Get("Referer")))
	}))
	defer srv.Close()

	assert.Empty(t, run(t, srv, true, headerssti.Check).Observations)
}

func TestHeaderSSTI_NoReflection_NoFindings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	assert.Empty(t, run(t, srv, true, headerssti.Check).Observations)
}

func TestHeaderSSTI_NotAggressive_Skipped(t *testing.T) {
	srv := httptest.NewServer(evalBrace("Referer"))
	defer srv.Close()

	summary := run(t, srv, false, headerssti.Check)
	assert.Empty(t, summary.Observations)
	var skipped bool
	for _, r := range summary.Results {
		if r.CheckID == headerssti.Check.ID {
			skipped = r.Skipped
		}
	}
	assert.True(t, skipped, "check should skip without --aggressive")
}
