package probebase

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// ProbeRawPath sends one request with method to a literal, non-normalized
// request-target (rawPath) against baseURL's scheme/host. Unlike
// ProbePath/ResolvePath, which round-trip the path through net/url and
// re-escape it, this sends rawPath exactly as written on the wire — needed
// to test path-normalization bypass payloads (encoded traversal, duplicate
// slashes, semicolon parameters, ...) that a naive access-control check
// might treat differently than the backend that ultimately resolves them.
func ProbeRawPath(ctx context.Context, sctx *scanctx.ScanContext, baseURL, method, rawPath string) (*PathResult, error) {
	base, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	reqURL := &url.URL{Scheme: base.Scheme, Host: base.Host}
	// A payload containing "%" must go through Opaque so it reaches the
	// wire undecoded — Path alone would have url.URL re-escape the "%"
	// itself. A payload without one (e.g. a duplicate-slash or
	// semicolon-parameter bypass) goes through Path directly, since Opaque
	// mangles a leading "//" into a scheme-relative authority.
	if strings.Contains(rawPath, "%") {
		reqURL.Opaque = rawPath
	} else {
		reqURL.Path = rawPath
	}

	req := (&http.Request{
		Method: method,
		URL:    reqURL,
		Host:   base.Host,
		Header: make(http.Header),
	}).WithContext(ctx)

	fetched, err := do(sctx.HTTPClient, req)
	if err != nil {
		return nil, err
	}
	return &PathResult{
		Path:       rawPath,
		StatusCode: fetched.StatusCode,
		Header:     fetched.Header,
		Body:       fetched.Body,
		Err:        fetched.Err,
	}, nil
}
