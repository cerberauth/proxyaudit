package probebase

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/url"

	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// WAFRequest is one request of a WAF probe: a method, a literal query
// string (sent as-is, so an encoded payload reaches the wire undecoded),
// and an optional body.
type WAFRequest struct {
	Method   string
	RawQuery string
	Header   http.Header
	Body     []byte
}

// WAFDelivery is a way of getting a value to the target — in the query
// string, or in a request body of a given content type/encoding.
type WAFDelivery struct {
	Name  string
	Build func(param, value string) WAFRequest
}

// QueryRequest builds a GET carrying rawQuery verbatim.
func QueryRequest(rawQuery string) WAFRequest {
	return WAFRequest{Method: http.MethodGet, RawQuery: rawQuery}
}

func bodyRequest(contentType string, body []byte) WAFRequest {
	return WAFRequest{Method: http.MethodPost, Header: http.Header{"Content-Type": {contentType}}, Body: body}
}

// QueryDelivery sends the value as a query-string parameter.
var QueryDelivery = WAFDelivery{"query string", func(param, value string) WAFRequest {
	return QueryRequest(param + "=" + QueryValue(value))
}}

// WAFDeliveries lists every delivery the content-type consistency check
// compares, QueryDelivery first.
var WAFDeliveries = []WAFDelivery{
	QueryDelivery,
	{"application/x-www-form-urlencoded body", func(param, value string) WAFRequest {
		return bodyRequest("application/x-www-form-urlencoded", []byte(url.Values{param: {value}}.Encode()))
	}},
	{"application/json body", func(param, value string) WAFRequest {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]string{param: value})
		return bodyRequest("application/json", buf.Bytes())
	}},
	{"multipart/form-data body", func(param, value string) WAFRequest {
		var buf bytes.Buffer
		w := multipart.NewWriter(&buf)
		_ = w.WriteField(param, value)
		_ = w.Close()
		return bodyRequest(w.FormDataContentType(), buf.Bytes())
	}},
	{"text/plain body", func(param, value string) WAFRequest {
		return bodyRequest("text/plain", []byte(param+"="+value))
	}},
	{"gzip-encoded form body", func(param, value string) WAFRequest {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		_, _ = zw.Write([]byte(url.Values{param: {value}}.Encode()))
		_ = zw.Close()
		req := bodyRequest("application/x-www-form-urlencoded", buf.Bytes())
		req.Header.Set("Content-Encoding", "gzip")
		return req
	}},
}

// ProbeWAF sends wr to baseURL's path (existing query and fragment
// stripped).
func ProbeWAF(ctx context.Context, sctx *scanctx.ScanContext, baseURL string, wr WAFRequest) (*FetchResult, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}
	u.RawQuery = wr.RawQuery
	u.Fragment = ""

	req, err := http.NewRequestWithContext(ctx, wr.Method, u.String(), bytes.NewReader(wr.Body))
	if err != nil {
		return nil, err
	}
	for name, values := range wr.Header {
		req.Header[name] = values
	}
	return do(sctx.HTTPClient, req)
}

// wafBlockStatuses are the statuses WAFs and filtering proxies answer a
// rejected request with.
var wafBlockStatuses = map[int]bool{
	http.StatusBadRequest:                 true,
	http.StatusForbidden:                  true,
	http.StatusNotAcceptable:              true,
	http.StatusTeapot:                     true,
	http.StatusTooManyRequests:            true,
	http.StatusUnavailableForLegalReasons: true,
	http.StatusNotImplemented:             true,
}

// WAFControlUsable reports whether a benign control response can serve as
// the "not blocked" reference: it must have succeeded and must not itself
// look like a rejection, or a blocked payload couldn't be told apart from
// it.
func WAFControlUsable(control *FetchResult) bool {
	return control.Err == nil && !wafBlockStatuses[control.StatusCode]
}

// WAFBlocked reports whether probe — a request carrying a payload — was
// rejected, judged against control, the same request shape carrying
// WAFBenignValue: a dropped connection, or a rejection status the control
// didn't get. Anything else (including a backend error) means the payload
// got through the filtering layer.
func WAFBlocked(control, probe *FetchResult) bool {
	if probe.Err != nil {
		return true
	}
	return probe.StatusCode != control.StatusCode && wafBlockStatuses[probe.StatusCode]
}
