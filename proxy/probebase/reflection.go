package probebase

import (
	"bytes"
	"context"
	"net/http"
	"strings"

	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// SpoofedIPMarker is a distinctive, non-routable (TEST-NET-3, RFC 5737)
// value injected into client-IP-ish trust-boundary test headers, so a
// later reflection of it in the response can be attributed to that header
// with high confidence rather than a coincidental match.
const SpoofedIPMarker = "203.0.113.42"

// SpoofedHostMarker is a distinctive hostname injected into
// X-Forwarded-Host-style trust-boundary tests.
const SpoofedHostMarker = "proxyaudit-trust-probe.invalid"

// SpoofedForwardedMarker is a distinct TEST-NET-3 address from
// SpoofedIPMarker, used in the RFC 7239 Forwarded header side of the
// forwarded_consistency check so its reflection can be told apart from a
// simultaneously sent X-Forwarded-For value.
const SpoofedForwardedMarker = "203.0.113.99"

// ReflectionResult is the outcome of a single header-injection reflection
// probe: whether the marker sent in a request header comes back in the
// response body or in a response header, which would indicate the proxy
// (or an origin it trusts blindly) treats that client-supplied header as
// authoritative.
type ReflectionResult struct {
	StatusCode      int
	Header          http.Header
	Body            []byte
	ReflectedInBody bool
	ReflectedHeader string // response header name the marker was found in, if any
	Err             error
}

// ProbeWithHeader sends one GET to url with headerName set to headerValue,
// and reports whether marker appears in the response body or in any
// response header.
func ProbeWithHeader(ctx context.Context, sctx *scanctx.ScanContext, url, headerName, headerValue, marker string) (*ReflectionResult, error) {
	return ProbeWithHeaders(ctx, sctx, url, map[string]string{headerName: headerValue}, marker)
}

// ProbeWithHeaders sends one GET to url with every entry in headers set,
// and reports whether marker appears in the response body or in any
// response header. Used by checks that need to send more than one
// trust-boundary header in the same request (e.g. comparing RFC 7239
// Forwarded against legacy headers).
func ProbeWithHeaders(ctx context.Context, sctx *scanctx.ScanContext, url string, headers map[string]string, marker string) (*ReflectionResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for name, value := range headers {
		req.Header.Set(name, value)
	}

	// Reflection is judged on the immediate response, not wherever a
	// redirect might lead (e.g. a spoofed X-Forwarded-Host reflected into
	// a Location header would otherwise send this probe off-target).
	client := &http.Client{
		Transport: sctx.HTTPClient.Transport,
		Timeout:   sctx.HTTPClient.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	fetched, err := do(client, req)
	if err != nil {
		return nil, err
	}
	if fetched.Err != nil {
		return &ReflectionResult{Err: fetched.Err}, nil
	}

	result := &ReflectionResult{StatusCode: fetched.StatusCode, Header: fetched.Header, Body: fetched.Body}
	result.ReflectedInBody, result.ReflectedHeader = FindMarker(fetched.Header, fetched.Body, marker)
	return result, nil
}

// FindMarker reports whether marker appears in body or in any header value,
// returning the header name it was found in (if any). Exposed for checks
// that send more than one marker in a single request (via
// ProbeWithHeaders) and need to test each marker's reflection separately
// against the one shared response.
func FindMarker(header http.Header, body []byte, marker string) (inBody bool, headerName string) {
	inBody = bytes.Contains(body, []byte(marker))
	for name, values := range header {
		for _, v := range values {
			if strings.Contains(v, marker) {
				return inBody, name
			}
		}
	}
	return inBody, ""
}

// Reflected reports whether r shows any reflection of the marker (body or
// header).
func (r *ReflectionResult) Reflected() bool {
	return r != nil && (r.ReflectedInBody || r.ReflectedHeader != "")
}
