package probebase

import (
	"context"
	"net/http"

	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// CORSOriginMarker is a distinctive attacker-controlled origin sent as the
// Origin header in CORS probes, so a reflection of it in
// Access-Control-Allow-Origin can be attributed to that header with high
// confidence rather than a coincidental match with the target's own origin.
const CORSOriginMarker = "https://proxyaudit-cors-probe.invalid"

// CORSResult is the outcome of a single cross-origin request (a simple
// request carrying an Origin header, or an OPTIONS preflight), used by
// checks/headers/cors to inspect the Access-Control-* response headers a
// browser would act on directly, rather than via body/header reflection.
type CORSResult struct {
	StatusCode int
	Header     http.Header
	Err        error
}

// ProbeCORS sends one request of method to url with every entry in headers
// set (typically Origin, and for a preflight
// Access-Control-Request-Method/-Headers), and returns the response so the
// caller can inspect the Access-Control-* response headers.
func ProbeCORS(ctx context.Context, sctx *scanctx.ScanContext, url, method string, headers map[string]string) (*CORSResult, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	fetched, err := do(sctx.HTTPClient, req)
	if err != nil {
		return nil, err
	}
	return &CORSResult{StatusCode: fetched.StatusCode, Header: fetched.Header, Err: fetched.Err}, nil
}
