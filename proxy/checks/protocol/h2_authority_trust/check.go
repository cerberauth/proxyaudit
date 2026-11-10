// Package h2authoritytrust tests the HTTP/2-specific pseudo-header
// conversion in item 1 of the protocol epic: a client over HTTP/2 supplies
// the target host in the :authority pseudo-header, which the proxy must
// convert to an HTTP/1.1 Host (or route on) for the backend. If the proxy
// trusts a client-supplied :authority it never validated — reflecting it,
// or routing on it — an attacker controls request routing / absolute-URL
// generation over the HTTP/2 control plane, the h2 analogue of Host-header
// injection.
//
// The probe sends a benign, distinctive marker as the :authority over a
// forced-HTTP/2 connection and reports a finding only when that marker
// comes back while a clean control request did not contain it. It needs
// HTTP/2 (ALPN "h2"); against an HTTP/1.1-only target it skips.
//
// Requires --aggressive: it sends a spoofed-authority probe, part of the
// opt-in attack-simulation suite.
package h2authoritytrust

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/checks/protocol/h2probe"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("h2_authority_trust", checkYAML)

// spoofedAuthority is a distinctive, non-routable hostname whose later
// reflection is attributable to the :authority we sent.
const spoofedAuthority = probebase.SpoofedHostMarker

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)
	if !sctx.Aggressive {
		return harnessx.Result{Skipped: true, SkipReason: "aggressive-suite check — rerun with --aggressive to send an HTTP/2 :authority probe"}, nil
	}

	// Control: an ordinary HTTP/2 request. If it can't be made, the target
	// doesn't speak HTTP/2 and the check doesn't apply. If the marker is
	// already present, reflection can't be attributed.
	control := h2probe.RoundTrip(ctx, sctx, target.URL, "", spoofedAuthority)
	if control.Err != nil {
		return harnessx.Result{Skipped: true, SkipReason: "target did not negotiate HTTP/2 (ALPN h2) — HTTP/2-specific check not applicable"}, nil
	}
	if control.ReflectedInBody || control.ReflectedHeader != "" {
		return harnessx.Result{Skipped: true, SkipReason: "control response already contains the probe marker — can't attribute a reflection to :authority"}, nil
	}

	probe := h2probe.RoundTrip(ctx, sctx, target.URL, spoofedAuthority, spoofedAuthority)
	if probe.Err != nil || !probe.Reflected() {
		return harnessx.Result{}, nil
	}

	where := "response body"
	if probe.ReflectedHeader != "" {
		where = "the " + probe.ReflectedHeader + " response header"
	}
	return harnessx.Result{Observations: []harnessx.Observation{{
		Title:       "Proxy trusts the client-supplied HTTP/2 :authority pseudo-header",
		Description: "Over HTTP/2, a request carrying :authority = " + spoofedAuthority + " (a host the client has no claim to) was reflected back in " + where + ", while a clean control request was not. The proxy converts/trusts the client-supplied :authority without validating it against its own configuration — the HTTP/2 analogue of Host-header injection, letting an attacker influence routing, cache keys, or absolute-URL generation via the h2 control plane.",
		Evidence:    ":authority: " + spoofedAuthority + " -> reflected in " + where,
		Metadata:    map[string]string{"authority": spoofedAuthority, "reflected_header": probe.ReflectedHeader},
	}}}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
