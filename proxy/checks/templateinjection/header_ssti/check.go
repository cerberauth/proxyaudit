// Package headerssti probes for server-side template injection in the
// proxy layer itself: a reverse proxy or gateway that renders a template
// engine over request headers it reflects back (Caddy's `templates`
// directive evaluating Go/sprig template syntax in a reflected Referer is
// the canonical case) will evaluate an expression an attacker plants in
// that header, turning header reflection into file read / environment
// disclosure.
//
// The probe is deliberately non-destructive: it injects only a benign
// arithmetic expression whose product is a distinctive, unlikely-to-
// collide integer, in several engine syntaxes, and reports a finding only
// when that product appears in the response while being absent from a
// clean control request — i.e. the expression was evaluated rather than
// echoed. It never attempts file reads, environment access, or any other
// side effect.
//
// Requires --aggressive: it sends crafted injection payloads in request
// headers, which belongs to the opt-in attack-simulation suite.
package headerssti

import (
	"context"
	_ "embed"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("header_ssti", checkYAML)

// product is the evaluated result shared by every payload (7919 * 8039).
// It is distinctive enough that its presence in a response that a clean
// control request lacked is attributable to the expression having been
// evaluated rather than reflected or coincidental.
const product = "63660841"

// payload is one template-engine syntax carrying the arithmetic
// expression, labelled by the engine family that evaluates it.
type payload struct {
	engine string
	expr   string
}

// payloads cover the brace syntax shared by Jinja2/Twig/Nunjucks, the Go
// text/template + sprig form Caddy's `templates` directive uses, and the
// JSP/Spring EL and Ruby/Thymeleaf expression forms — each a non-
// destructive multiplication.
var payloads = []payload{
	{"Jinja2/Twig/Nunjucks ({{ }})", "{{7919*8039}}"},
	{"Go text/template + sprig ({{mul }})", "{{mul 7919 8039}}"},
	{"JSP/Spring EL (${ })", "${7919*8039}"},
	{"Ruby/Thymeleaf (#{ })", "#{7919*8039}"},
}

// reflectiveHeaders are request headers a proxy commonly reflects into a
// response (an error page, a redirect, a debug echo), where a templating
// directive would evaluate them.
var reflectiveHeaders = []string{"Referer", "User-Agent", "X-Forwarded-Host"}

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)
	if !sctx.Aggressive {
		return harnessx.Result{Skipped: true, SkipReason: "aggressive-suite check — rerun with --aggressive to send template-injection probes"}, nil
	}

	// A control request with no payload: if the evaluated product already
	// appears in the ordinary response, reflections can't be told from
	// coincidence, so the check can't make a confident call.
	control, err := probebase.ProbeWithHeader(ctx, sctx, target.URL, "X-Proxyaudit-Probe", "control", product)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	if control.Err != nil {
		return harnessx.Result{Err: control.Err}, nil
	}
	if control.ReflectedInBody {
		return harnessx.Result{Skipped: true, SkipReason: "control response already contains the probe's expected value — can't attribute it to evaluation"}, nil
	}

	var observations []harnessx.Observation
	for _, hdr := range reflectiveHeaders {
		for _, p := range payloads {
			res, err := probebase.ProbeWithHeader(ctx, sctx, target.URL, hdr, p.expr, product)
			if err != nil {
				return harnessx.Result{Observations: observations, Err: err}, nil
			}
			if res.Err != nil || !res.ReflectedInBody {
				continue
			}
			// The product is present. If the literal expression is also
			// present the engine echoed it verbatim (no evaluation); a
			// finding needs the product without the raw expression.
			if strings.Contains(string(res.Body), p.expr) {
				continue
			}
			observations = append(observations, harnessx.Observation{
				Title:       "Request header " + hdr + " evaluated as a server-side template",
				Description: "The proxy rendered a " + p.engine + " expression supplied in the " + hdr + " request header: the benign expression " + p.expr + " came back evaluated to " + product + ", while a clean control request did not contain that value. A reflected request header is being passed through a template engine (e.g. Caddy's `templates` directive), so an attacker can substitute file-read or environment-disclosure expressions for this arithmetic one.",
				Evidence:    hdr + ": " + p.expr + " -> response contains " + product,
				Metadata:    map[string]string{"header": hdr, "engine": p.engine, "expression": p.expr},
			})
			break
		}
	}
	return harnessx.Result{Observations: observations}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
