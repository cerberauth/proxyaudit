// Package openforwardproxy tests whether the reverse proxy also behaves as
// an open forward proxy: given a request whose request-target is an
// absolute URI for an arbitrary external host, does it fetch that host on
// the client's behalf? That is the foundational SSRF / open-relay
// primitive — once it holds, an attacker reaches any host the proxy can.
//
// The probe sends an absolute-form request for the IANA example domain
// (example.com, reserved for exactly this kind of use) and confirms open-
// proxy behaviour only when the proxy returns that domain's recognizable
// content, which a request served by the real backend never contains. The
// scanner never contacts example.com directly — only the proxy does, and
// only if it forwards.
//
// Requires --aggressive: it induces the proxy to make an outbound request
// to a host of the scanner's choosing, part of the opt-in attack-
// simulation suite.
package openforwardproxy

import (
	"bytes"
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/checks/ssrf/ssrfprobe"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("open_forward_proxy", checkYAML)

// externalHost is IANA's reserved example domain; fetching it is harmless,
// and its page body carries markers no backend would emit by coincidence.
const externalHost = "example.com"

// forwardMarkers are strings from example.com's well-known page used to
// confirm the proxy actually fetched it.
var forwardMarkers = [][]byte{[]byte("Example Domain"), []byte("illustrative examples")}

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)
	if !sctx.Aggressive {
		return harnessx.Result{Skipped: true, SkipReason: "aggressive-suite check — rerun with --aggressive to send open-proxy probes"}, nil
	}

	// Baseline: an ordinary origin-form request served by the backend,
	// used to prove the forward markers aren't already present.
	control, err := ssrfprobe.RoundTrip(ctx, sctx, target.URL, "/", ssrfprobe.HostHeader(target.URL))
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	if marked(control.Body) {
		return harnessx.Result{Skipped: true, SkipReason: "backend response already contains the probe's forward markers — can't attribute them to forwarding"}, nil
	}

	probe, err := ssrfprobe.RoundTrip(ctx, sctx, target.URL, "http://"+externalHost+"/", externalHost)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	if !probe.Succeeded() || !marked(probe.Body) {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Observations: []harnessx.Observation{{
		Title:       "Proxy forwards absolute-URI requests to arbitrary external hosts (open proxy / SSRF)",
		Description: "An absolute-form request (GET http://" + externalHost + "/) sent to the proxy was fulfilled by fetching " + externalHost + " and returning its content, which the backend never serves. The proxy honors the client-supplied request-target authority instead of routing only to its configured backend, so an attacker can reach any host the proxy can — external or internal — turning the proxy into an open relay and SSRF pivot.",
		Evidence:    "GET http://" + externalHost + "/ -> " + ssrfprobe.BodySignature(probe.Body),
		Metadata:    map[string]string{"forwarded_host": externalHost},
	}}}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))

func marked(body []byte) bool {
	for _, m := range forwardMarkers {
		if bytes.Contains(body, m) {
			return true
		}
	}
	return false
}
