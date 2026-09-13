// Package xforwardedhost sends a spoofed X-Forwarded-Host value and checks
// whether it is reflected back in the response — e.g. in a redirect
// Location header or canonical link — which would indicate a host-header-
// poisoning-style trust issue (password reset links, cache poisoning).
package xforwardedhost

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

var Def = checkdef.MustParseCheckDefYAML("x_forwarded_host", checkYAML)

const headerName = "X-Forwarded-Host"

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	result, err := probebase.ProbeWithHeader(ctx, sctx, target.URL, headerName, probebase.SpoofedHostMarker, probebase.SpoofedHostMarker)
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
		Title:       "X-Forwarded-Host value trusted in response",
		Description: "A spoofed " + headerName + " value was reflected back in the response, suggesting the proxy or origin uses this client-supplied header to build absolute URLs (e.g. redirects, canonical links) — a host-header-poisoning risk.",
		Evidence:    "sent " + headerName + ": " + probebase.SpoofedHostMarker + "; reflected in " + reflectionLocation(result),
		Metadata:    map[string]string{"header": headerName},
	}}}, nil
})

func reflectionLocation(r *probebase.ReflectionResult) string {
	if r.ReflectedHeader != "" {
		return "response header " + r.ReflectedHeader
	}
	return "response body"
}
