// Package ambiguousframing tests how the proxy handles requests whose
// message length is ambiguous — the precondition for every classic
// request-smuggling / desync attack (CL.TE, TE.CL, TE.TE). RFC 9112
// requires a server to reject a message that carries conflicting
// Content-Length values, or both Content-Length and Transfer-Encoding, or
// an unrecognized Transfer-Encoding. A front-end that instead accepts such
// a message, and a back-end that resolves the length differently, is a
// desync waiting to happen.
//
// The probe never performs an actual desync: it sends only benign,
// self-contained bodies and never tries to smuggle a second request, so it
// cannot poison another client's connection (each probe uses its own
// Connection: close socket). It reports purely on whether the ambiguous
// message was rejected (a 4xx/5xx or a dropped connection) or accepted (a
// 2xx/3xx) — acceptance being the smuggling precondition.
//
// Requires --aggressive: it puts deliberately malformed requests on the
// wire, part of the opt-in attack-simulation suite.
package ambiguousframing

import (
	"context"
	_ "embed"
	"net/http"
	"net/url"
	"strconv"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/checks/smuggling/smugprobe"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("ambiguous_framing", checkYAML)

const crlf = "\r\n"

// variant is one ambiguous-framing message shape.
type variant struct {
	id      string
	title   string
	why     string
	headers string // header lines (each ending in CRLF) after Host/Connection
	body    string
}

// variants are RFC-violating framings a conformant proxy must reject. Each
// body is self-contained and bounded so no probe can hang a length-honoring
// parser waiting for bytes that never arrive.
var variants = []variant{
	{
		id:      "duplicate_content_length",
		title:   "conflicting duplicate Content-Length",
		why:     "two Content-Length headers with different values — a front-end and back-end that pick different ones disagree on where the request ends",
		headers: "Content-Length: 6" + crlf + "Content-Length: 5" + crlf,
		body:    "AAAAAA", // 6 bytes; both lengths are satisfiable, so no parser stalls
	},
	{
		id:      "cl_te",
		title:   "both Content-Length and Transfer-Encoding",
		why:     "Content-Length and Transfer-Encoding: chunked together — the CL.TE / TE.CL ambiguity, where one hop honors the length and the other the chunking",
		headers: "Content-Length: 6" + crlf + "Transfer-Encoding: chunked" + crlf,
		body:    "0" + crlf + crlf + "X", // valid empty chunk (5 bytes) + 1 pad byte = 6, satisfies CL too
	},
	{
		id:      "te_obfuscated_value",
		title:   "Transfer-Encoding with an unrecognized final encoding",
		why:     "two Transfer-Encoding headers where the final one isn't chunked — a hop that reads the first chunks the body, a hop that reads the last doesn't (TE.TE)",
		headers: "Transfer-Encoding: chunked" + crlf + "Transfer-Encoding: identity" + crlf,
		body:    "0" + crlf + crlf,
	},
	{
		id:      "te_obfuscated_name",
		title:   "whitespace-obfuscated Transfer-Encoding header name",
		why:     "a space before the colon in \"Transfer-Encoding : chunked\" — a strict parser ignores the header, a lenient one honors the chunking, so the two hops frame the body differently",
		headers: "Transfer-Encoding : chunked" + crlf,
		body:    "0" + crlf + crlf,
	},
}

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)
	if !sctx.Aggressive {
		return harnessx.Result{Skipped: true, SkipReason: "aggressive-suite check — rerun with --aggressive to send ambiguous-framing probes"}, nil
	}

	tgt, err := smugprobe.NewTarget(sctx, target.URL)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	path := requestPath(target.URL)

	// Baseline: a well-formed POST with a correct Content-Length must be
	// accepted, or the endpoint rejects everything and acceptance of a
	// malformed variant can't be read as a framing weakness.
	control := tgt.Send(ctx, build(path, tgt.Host(), "Content-Length: 6"+crlf, "AAAAAA"))
	if control.Rejected() {
		return harnessx.Result{Skipped: true, SkipReason: "endpoint rejects a well-formed POST (" + describe(control) + ") — can't establish a baseline to judge ambiguous framing against"}, nil
	}

	var observations []harnessx.Observation
	for _, v := range variants {
		resp := tgt.Send(ctx, build(path, tgt.Host(), v.headers, v.body))
		if resp.Rejected() {
			continue
		}
		observations = append(observations, harnessx.Observation{
			Title:       "Proxy accepts ambiguous request framing (" + v.title + ")",
			Description: "A request with " + v.why + " was accepted by the proxy (" + describe(resp) + ") instead of being rejected as RFC 9112 requires. If the back-end resolves the message length differently from this front-end, the mismatch is a request-smuggling / desync primitive. This check does not attempt the desync itself — it reports only that the malformed framing was not rejected.",
			Evidence:    "POST " + path + " with " + v.title + " -> " + describe(resp) + "; well-formed control -> " + describe(control),
			Metadata:    map[string]string{"variant": v.id, "status": statusText(resp)},
		})
	}
	return harnessx.Result{Observations: observations}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))

// build assembles a raw HTTP/1.1 request from a path, host, extra header
// lines (each CRLF-terminated), and a body sent verbatim.
func build(path, host, headers, body string) string {
	return "POST " + path + " HTTP/1.1" + crlf +
		"Host: " + host + crlf +
		"User-Agent: proxyaudit" + crlf +
		"Connection: close" + crlf +
		headers + crlf + body
}

func requestPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.RequestURI() == "" {
		return "/"
	}
	return u.RequestURI()
}

func describe(r *smugprobe.Response) string {
	if r.Err != nil {
		return "connection dropped/failed"
	}
	return statusText(r)
}

func statusText(r *smugprobe.Response) string {
	if r.Err != nil {
		return "no response"
	}
	return strconv.Itoa(r.StatusCode) + " " + http.StatusText(r.StatusCode)
}
