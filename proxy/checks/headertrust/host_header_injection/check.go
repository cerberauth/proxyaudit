// Package hostheaderinjection sends a spoofed Host header — distinct from
// X-Forwarded-Host, which req.Header.Set cannot override for the actual
// Host line net/http sends — and checks whether it is reflected back in
// the response, e.g. in a redirect Location header or a generated
// absolute link, which would indicate the origin trusts the
// client-supplied Host header directly to build absolute URLs
// (password-reset links, cache poisoning).
package hostheaderinjection

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

var Def = checkdef.MustParseCheckDefYAML("host_header_injection", checkYAML)

// candidatePaths are the root plus common password-reset endpoint
// conventions most likely to build an absolute URL (e.g. a reset link)
// straight from the request's Host header.
var candidatePaths = []string{"/", "/password-reset", "/reset-password", "/forgot-password"}

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	for _, path := range candidatePaths {
		url, err := probebase.ResolvePath(target.URL, path)
		if err != nil {
			return harnessx.Result{Err: err}, nil
		}

		result, err := probebase.ProbeWithHost(ctx, sctx, url, probebase.SpoofedHostMarker, probebase.SpoofedHostMarker)
		if err != nil {
			return harnessx.Result{Err: err}, nil
		}
		if result.Err != nil || !result.Reflected() {
			continue
		}

		return harnessx.Result{Observations: []harnessx.Observation{{
			Title:       "Host header value trusted in response",
			Description: "A spoofed Host header value was reflected back in the response, suggesting the origin builds absolute URLs (e.g. password-reset links, redirects, canonical links) directly from the client-supplied Host header — a host-header-injection/poisoning risk.",
			Evidence:    "GET " + path + " with Host: " + probebase.SpoofedHostMarker + "; reflected in " + reflectionLocation(result),
			Metadata:    map[string]string{"header": "Host", "path": path},
		}}}, nil
	}

	return harnessx.Result{}, nil
})

func reflectionLocation(r *probebase.ReflectionResult) string {
	if r.ReflectedHeader != "" {
		return "response header " + r.ReflectedHeader
	}
	return "response body"
}
