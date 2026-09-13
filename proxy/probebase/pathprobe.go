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
