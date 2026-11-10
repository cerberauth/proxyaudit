// Package h2probe sends requests over a forced HTTP/2 connection (ALPN
// "h2"), so a check can exercise HTTP/2-specific behaviour — here, whether
// the proxy trusts the client-supplied :authority pseudo-header — rather
// than whatever protocol net/http happens to negotiate. It forces HTTP/2
// through the standard library's http.Transport (Protocols), not raw
// framing.
package h2probe

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"

	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

const maxBodyBytes = 1 << 20 // 1 MiB

// Result is one HTTP/2 round-trip. Err is set when an HTTP/2 connection
// could not be established at all (no ALPN "h2"), which callers read as
// "target does not speak HTTP/2" and skip.
type Result struct {
	StatusCode      int
	Proto           string
	Header          http.Header
	Body            []byte
	ReflectedInBody bool
	ReflectedHeader string
	Err             error
}

// Reflected reports whether the marker came back in the body or a header.
func (r *Result) Reflected() bool {
	return r != nil && r.Err == nil && (r.ReflectedInBody || r.ReflectedHeader != "")
}

// RoundTrip sends one GET to url over HTTP/2. When authority is non-empty
// it is sent as the :authority pseudo-header (net/http derives :authority
// from Request.Host), modelling a client that supplies an authority the
// transport peer didn't. It reports whether marker is reflected in the
// response.
func RoundTrip(ctx context.Context, sctx *scanctx.ScanContext, url, authority, marker string) *Result {
	// Force HTTP/2 only: ALPN must negotiate "h2" or the round-trip fails,
	// which callers read as "no HTTP/2" and skip.
	var protocols http.Protocols
	protocols.SetHTTP2(true)
	protocols.SetHTTP1(false)
	tr := &http.Transport{TLSClientConfig: tlsConfig(sctx), Protocols: &protocols}
	defer tr.CloseIdleConnections()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return &Result{Err: err}
	}
	if authority != "" {
		req.Host = authority // becomes the :authority pseudo-header
	}

	resp, err := tr.RoundTrip(req)
	if err != nil {
		return &Result{Err: err}
	}
	defer resp.Body.Close()
	// Guard against any HTTP/1.1 fallback: this check is HTTP/2-specific,
	// so a non-h2 response means the target doesn't offer HTTP/2 and the
	// caller should skip.
	if resp.ProtoMajor != 2 {
		return &Result{Err: fmt.Errorf("target negotiated %s, not HTTP/2", resp.Proto)}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))

	inBody, header := probebase.FindMarker(resp.Header, body, marker)
	return &Result{
		StatusCode:      resp.StatusCode,
		Proto:           resp.Proto,
		Header:          resp.Header,
		Body:            body,
		ReflectedInBody: inBody,
		ReflectedHeader: header,
	}
}

// tlsConfig mirrors the scan client's trust settings (so a test server's
// self-signed cert, or an --insecure scan, works over the forced-h2
// connection) and pins ALPN to h2.
func tlsConfig(sctx *scanctx.ScanContext) *tls.Config {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12, NextProtos: []string{"h2"}}
	if t, ok := sctx.HTTPClient.Transport.(*http.Transport); ok && t.TLSClientConfig != nil {
		cfg.RootCAs = t.TLSClientConfig.RootCAs
		cfg.InsecureSkipVerify = t.TLSClientConfig.InsecureSkipVerify
		cfg.ServerName = t.TLSClientConfig.ServerName
	}
	if sctx.RootCAs != nil {
		cfg.RootCAs = sctx.RootCAs
	}
	return cfg
}
