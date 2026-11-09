// Package internaltargetaccess builds on the open-proxy primitive: when
// the proxy honors absolute-form request-targets, it probes whether that
// reaches hosts the client should never be able to — the proxy's own
// loopback interface, link-local cloud-metadata endpoints, and private
// (RFC 1918) ranges. Reachability of any of these is the high-impact SSRF
// case (credential theft via the metadata service, access to internal-
// only admin surfaces).
//
// Detection is differential and conservative: it first asks the proxy to
// forward to a host guaranteed not to resolve, establishing how the proxy
// answers a forward it cannot fulfil. Only if that baseline is a distinct
// failure (so forwarding can be told from the proxy simply serving its
// backend) does it probe the internal targets, flagging each whose
// response is a success distinct from that baseline. If the baseline
// itself succeeds — the proxy serves its backend for any authority, i.e.
// it is not forwarding — the check skips rather than guess.
//
// Requires --aggressive: it induces outbound requests to internal hosts,
// part of the opt-in attack-simulation suite.
package internaltargetaccess

import (
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

var Def = checkdef.MustParseCheckDefYAML("internal_target_access", checkYAML)

// unresolvableHost establishes the proxy's "can't forward" baseline: a
// .invalid name (RFC 6761) never resolves, so a forwarding proxy fails it.
const unresolvableHost = "proxyaudit-ssrf-nx.invalid"

// internalTarget is an authority a client should never reach through a
// correctly scoped proxy.
type internalTarget struct {
	host string
	kind string
}

var internalTargets = []internalTarget{
	{"127.0.0.1", "proxy loopback interface"},
	{"localhost", "proxy loopback interface"},
	{"[::1]", "proxy loopback interface (IPv6)"},
	{"169.254.169.254", "link-local cloud metadata (AWS/Azure/OpenStack IMDS)"},
	{"metadata.google.internal", "GCP metadata service"},
	{"10.0.0.1", "private RFC 1918 range (10.0.0.0/8)"},
	{"192.168.0.1", "private RFC 1918 range (192.168.0.0/16)"},
}

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)
	if !sctx.Aggressive {
		return harnessx.Result{Skipped: true, SkipReason: "aggressive-suite check — rerun with --aggressive to send internal-target SSRF probes"}, nil
	}

	baseline, err := ssrfprobe.RoundTrip(ctx, sctx, target.URL, "http://"+unresolvableHost+"/", unresolvableHost)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	// A distinct "can't forward" baseline is a connection error, a gateway
	// status, or a client-side rejection. If instead the proxy answered a
	// forward to a nonexistent host with a normal success, it is serving
	// its backend regardless of authority (not forwarding at all) and
	// internal reachability can't be inferred.
	if !distinctFailure(baseline) {
		return harnessx.Result{Skipped: true, SkipReason: "proxy serves its backend for an unresolvable forward target — absolute-URI forwarding not in effect, nothing to probe"}, nil
	}

	var observations []harnessx.Observation
	for _, t := range internalTargets {
		r, err := ssrfprobe.RoundTrip(ctx, sctx, target.URL, "http://"+t.host+"/", t.host)
		if err != nil {
			return harnessx.Result{Observations: observations, Err: err}, nil
		}
		// Reached the internal host: a success response (the proxy
		// connected and got an answer) distinct from the can't-forward
		// baseline.
		if !r.Succeeded() || r.StatusCode >= 500 || sameOutcome(r, baseline) {
			continue
		}
		observations = append(observations, harnessx.Observation{
			Title:       "Proxy reaches internal host " + t.host + " via SSRF (" + t.kind + ")",
			Description: "An absolute-form request for http://" + t.host + "/ was forwarded by the proxy and returned a response distinct from how it answers an unreachable host — the proxy connected to " + t.host + " (" + t.kind + ") on the client's behalf. This exposes internal-only surfaces to any external client; the cloud metadata endpoint in particular can leak instance credentials.",
			Evidence:    "GET http://" + t.host + "/ -> " + status(r) + " " + ssrfprobe.BodySignature(r.Body) + "; unreachable baseline -> " + baselineDesc(baseline),
			Metadata:    map[string]string{"host": t.host, "kind": t.kind},
		})
	}
	return harnessx.Result{Observations: observations}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
