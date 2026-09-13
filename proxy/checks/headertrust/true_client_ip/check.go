// Package trueclientip sends a spoofed True-Client-IP value (Akamai-style
// single-hop header) and checks whether it is reflected back in the
// response, tested independently of X-Forwarded-For and X-Real-IP.
package trueclientip

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

var Def = checkdef.MustParseCheckDefYAML("true_client_ip", checkYAML)

const headerName = "True-Client-IP"

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
		Title:       "True-Client-IP value reflected in response",
		Description: "A spoofed " + headerName + " value was reflected back in the response, suggesting the proxy or an origin it trusts treats this single-hop client-supplied header as authoritative.",
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
