package probebase

import (
	"context"
	"net/http"
	"net/url"

	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// PathResult is the outcome of a single GET to a specific path on the
// target, used by checks/disclosure to probe a fixed list of
// exposure-prone paths.
type PathResult struct {
	Path       string
	StatusCode int
	Header     http.Header
	Body       []byte
	Err        error
}

// ProbePath sends one GET to path resolved against baseURL (query and
// fragment stripped).
func ProbePath(ctx context.Context, sctx *scanctx.ScanContext, baseURL, path string) (*PathResult, error) {
	return ProbePathWithHeaders(ctx, sctx, baseURL, path, nil)
}

// ProbePathWithHeaders sends one GET to path resolved against baseURL
// (query and fragment stripped) with every entry in headers set. Used by
// checks that need to compare a path's behavior with and without a
// client-supplied header (e.g. an ACL bypassed via a spoofed client-IP
// header).
func ProbePathWithHeaders(ctx context.Context, sctx *scanctx.ScanContext, baseURL, path string, headers map[string]string) (*PathResult, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	u.Path = path
	u.RawQuery = ""
	u.Fragment = ""

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
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
	return &PathResult{
		Path:       path,
		StatusCode: fetched.StatusCode,
		Header:     fetched.Header,
		Body:       fetched.Body,
		Err:        fetched.Err,
	}, nil
}
