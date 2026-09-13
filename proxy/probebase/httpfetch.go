// Package probebase holds the HTTP/TLS probe plumbing shared across
// proxy's check categories (a single GET, a TLS handshake, a
// header-reflection probe, a path probe) so individual checks only need to
// supply what makes them different, mirroring jwtop's checkbase package.
package probebase

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// ErrFetchUnavailable is returned by checks depending on HTTPFetchCheckID
// when the shared fetch failed or hasn't run — SkipUnlessFetched normally
// prevents a check's Run from being reached in that state, so this only
// surfaces if a check calls Fetch itself without wiring that skip.
var ErrFetchUnavailable = errors.New("probebase: shared HTTP fetch result unavailable")

// SkipUnlessFetched is a checkdef.WithSkip SkipDecision for any check that
// depends on HTTPFetchCheckID: it skips the check when the shared fetch
// errored, so every checks/headers (and checks/tls/hsts) check doesn't
// need to repeat that guard.
var SkipUnlessFetched = harnessx.SkipWhen(func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) string {
	fetched, ok := Fetch(store)
	if !ok || fetched.Err != nil {
		return "shared HTTP fetch failed — see probe.http_fetch"
	}
	return ""
})

// HTTPFetchCheckID is the shared check every checks/headers and
// checks/tls (HSTS, redirect) check depends on, so the target is only
// fetched once per scan.
const HTTPFetchCheckID harnessx.CheckID = "probe.http_fetch"

// MaxBodyBytes caps how much of a response body proxy buffers in memory.
const MaxBodyBytes = 1 << 20 // 1 MiB

// FetchResult is the shared HTTP response every http-fetch-dependent check
// inspects.
type FetchResult struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Err        error
}

// HTTPFetchCheck performs the single shared GET request against the
// target. It does not itself report a finding — it only exists to make the
// request once and expose the response via ResultStore.
var HTTPFetchCheck = checkdef.NewCheck(
	checkdef.CheckDef{ID: string(HTTPFetchCheckID), Name: "HTTP Fetch"},
	func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
		sctx := scanctx.TargetContext(target)

		req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.URL, nil)
		if err != nil {
			return harnessx.DataResult(&FetchResult{Err: err}), nil
		}

		result, err := do(sctx.HTTPClient, req)
		if err != nil {
			return harnessx.DataResult(&FetchResult{Err: err}), nil
		}
		return harnessx.DataResult(result), nil
	},
)

func do(client *http.Client, req *http.Request) (*FetchResult, error) {
	resp, err := client.Do(req)
	if err != nil {
		return &FetchResult{Err: err}, nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes))
	return &FetchResult{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

// Fetch reads the shared FetchResult off store, populated by
// HTTPFetchCheck. Checks that depend on HTTPFetchCheckID call this instead
// of making their own request.
func Fetch(store harnessx.ResultStore) (*FetchResult, bool) {
	return harnessx.GetData[*FetchResult](store, HTTPFetchCheckID)
}
