// Package smugprobe sends a byte-for-byte request over a raw TCP (or TLS)
// connection, bypassing net/http's request writer entirely so a check can
// put duplicate Content-Length headers, conflicting framing, and
// obfuscated Transfer-Encoding on the wire — things the standard client
// sanitizes away. Each send uses its own connection with Connection:
// close, so an ambiguous message can only desync the probe's own socket,
// never a reused one serving another client.
package smugprobe

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

const maxBodyBytes = 1 << 15 // 32 KiB

// Response is one raw send's outcome. Err is set when the connection
// failed or no response could be read (e.g. the proxy dropped the
// connection on a malformed message, which counts as a rejection).
type Response struct {
	StatusCode int
	Header     http.Header
	Err        error
}

// Rejected reports whether the message was refused: a dropped/failed
// connection, or a 4xx/5xx status. A sub-400 status means the proxy
// accepted the message and passed it on.
func (r *Response) Rejected() bool {
	return r == nil || r.Err != nil || r.StatusCode >= 400
}

// Target carries the parsed destination so a check can send many messages
// to the same host cheaply.
type Target struct {
	sctx *scanctx.ScanContext
	addr string
	host string
	tls  bool
}

// NewTarget parses baseURL into a reusable send Target.
func NewTarget(sctx *scanctx.ScanContext, baseURL string) (*Target, error) {
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
	return &Target{sctx: sctx, addr: net.JoinHostPort(host, port), host: host, tls: u.Scheme == "https"}, nil
}

// Host returns the authority to use in a Host header for this target.
func (t *Target) Host() string { return t.addr }

// Send writes raw verbatim and reads the response.
func (t *Target) Send(ctx context.Context, raw string) *Response {
	timeout := t.sctx.HTTPClient.Timeout
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", t.addr)
	if err != nil {
		return &Response{Err: err}
	}
	defer conn.Close()

	if t.tls {
		tlsConn := tls.Client(conn, t.tlsConfig())
		if err := tlsConn.HandshakeContext(dialCtx); err != nil {
			return &Response{Err: err}
		}
		conn = tlsConn
	}
	if deadline, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	if _, err := io.WriteString(conn, raw); err != nil {
		return &Response{Err: err}
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), &http.Request{Method: http.MethodPost})
	if err != nil {
		return &Response{Err: err}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxBodyBytes))
	return &Response{StatusCode: resp.StatusCode, Header: resp.Header}
}

func (t *Target) tlsConfig() *tls.Config {
	cfg := &tls.Config{ServerName: t.host, MinVersion: tls.VersionTLS12}
	if tr, ok := t.sctx.HTTPClient.Transport.(*http.Transport); ok && tr.TLSClientConfig != nil {
		cfg.RootCAs = tr.TLSClientConfig.RootCAs
		cfg.InsecureSkipVerify = tr.TLSClientConfig.InsecureSkipVerify
	}
	if t.sctx.RootCAs != nil {
		cfg.RootCAs = t.sctx.RootCAs
	}
	return cfg
}
