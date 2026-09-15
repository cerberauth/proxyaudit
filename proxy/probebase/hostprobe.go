package probebase

import (
	"context"
	"net/http"

	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// HostResult is the outcome of a single GET to a URL with the Host header
// optionally overridden, used by checks that test routing/trust decisions
// keyed on the client-supplied Host header rather than the connection the
// request arrived on.
type HostResult struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Err        error
}

// FetchWithHost sends one GET to url, overriding the request's Host header
// to host when non-empty (the connection is still made to url's own
// address — only the Host header line changes). An empty host leaves the
// request unmodified, for use as a same-request baseline.
func FetchWithHost(ctx context.Context, sctx *scanctx.ScanContext, url, host string) (*HostResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if host != "" {
		req.Host = host
	}

	fetched, err := do(sctx.HTTPClient, req)
	if err != nil {
		return nil, err
	}
	return &HostResult{StatusCode: fetched.StatusCode, Header: fetched.Header, Body: fetched.Body, Err: fetched.Err}, nil
}
