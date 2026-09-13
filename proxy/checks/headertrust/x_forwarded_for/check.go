// Package xforwardedfor sends a spoofed X-Forwarded-For value and checks
// whether it is reflected back in the response — a black-box heuristic for
// "does the proxy or origin trust this client-supplied header", since
// proxy has no visibility into what actually reaches the origin.
package xforwardedfor

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("x_forwarded_for", checkYAML)

const headerName = "X-Forwarded-For"

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	result, err := probebase.ProbeWithHeader(ctx, sctx, target.URL, headerName, probebase.SpoofedIPMarker, probebase.SpoofedIPMarker)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	if result.Err != nil {
		return harnessx.Result{Err: result.Err}, nil
	}
	if !result.Reflected() {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Observations: []harnessx.Observation{{
		Title:       "X-Forwarded-For value reflected in response",
		Description: "A spoofed " + headerName + " value was reflected back in the response, suggesting the proxy or an origin it trusts treats this client-supplied header as authoritative rather than appending to or discarding it.",
		Evidence:    "sent " + headerName + ": " + probebase.SpoofedIPMarker + "; reflected in " + reflectionLocation(result),
		Metadata:    map[string]string{"header": headerName},
	}}}, nil
})

func reflectionLocation(r *probebase.ReflectionResult) string {
	if r.ReflectedHeader != "" {
		return "response header " + r.ReflectedHeader
	}
	return "response body"
}
