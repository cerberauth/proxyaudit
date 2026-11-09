// Package ssrfprobe sends HTTP requests with a literal, caller-chosen
// request-target line against the target's host — specifically the
// absolute-form target (`GET http://host/path HTTP/1.1`) that exercises
// open-proxy / SSRF behaviour. net/http only emits an absolute-form
// target in forward-proxy mode, so the probe writes the request line by
// hand over a raw TCP (or TLS) connection and parses the response with
// net/http's own reader.
package ssrfprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// maxBodyBytes caps how much of a response body the probe buffers.
const maxBodyBytes = 1 << 16 // 64 KiB — enough to fingerprint, not the whole page.

// Response is one raw round-trip's outcome. Err is set when the connection
// could not be established or the response could not be read (e.g. the
// proxy dropped the connection); the status fields are then zero.
type Response struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	Err        error
}

// Succeeded reports whether a response line was read at all.
func (r *Response) Succeeded() bool { return r != nil && r.Err == nil && r.StatusCode != 0 }

// RoundTrip opens one connection to baseURL's host and sends a GET whose
// request-target is requestTarget (sent verbatim) with the given Host
// header. Passing an origin-form target ("/") makes an ordinary request;
// passing an absolute-form target ("http://other.host/") exercises
// forward-proxy handling.
func RoundTrip(ctx context.Context, sctx *scanctx.ScanContext, baseURL, requestTarget, hostHeader string) (*Response, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return nil, err
	}

	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(host, port)

	timeout := sctx.HTTPClient.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		return &Response{Err: err}, nil
	}
	defer conn.Close()

	if u.Scheme == "https" {
		tlsConn := tls.Client(conn, tlsConfig(sctx, host))
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			return &Response{Err: err}, nil
		}
		conn = tlsConn
	}

	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: proxyaudit\r\nAccept: */*\r\nConnection: close\r\n\r\n", requestTarget, hostHeader)
	if _, err := io.WriteString(conn, req); err != nil {
		return &Response{Err: err}, nil
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return &Response{Err: err}, nil
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes))
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}, nil
}

// tlsConfig mirrors the trust settings of the scan's HTTP client (so a
// test server's self-signed cert, or a --insecure scan, behaves the same
// over the raw connection) while pinning the SNI/ServerName to host.
func tlsConfig(sctx *scanctx.ScanContext, host string) *tls.Config {
	cfg := &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}
	if t, ok := sctx.HTTPClient.Transport.(*http.Transport); ok && t.TLSClientConfig != nil {
		src := t.TLSClientConfig
		cfg.RootCAs = src.RootCAs
		cfg.InsecureSkipVerify = src.InsecureSkipVerify
	}
	if sctx.RootCAs != nil {
		cfg.RootCAs = sctx.RootCAs
	}
	return cfg
}

// HostHeader returns the authority (host, with port if non-default) to
// send as the Host header for an ordinary request to baseURL.
func HostHeader(baseURL string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return baseURL
	}
	return u.Host
}

// BodySignature returns a short, comparable fingerprint of a response body
// (its length and leading bytes), for telling "served the real backend"
// apart from "forwarded somewhere else" without embedding whole pages in
// evidence.
func BodySignature(body []byte) string {
	head := body
	if len(head) > 48 {
		head = head[:48]
	}
	return fmt.Sprintf("%d bytes: %q", len(body), strings.TrimSpace(string(head)))
}
