// Package forwardedconsistency sends distinct spoofed values in the
// RFC 7239 Forwarded header and the legacy X-Forwarded-For header in the
// same request, and checks whether both are honored/reflected — which
// would indicate the proxy and origin disagree on which client-IP header
// is authoritative.
package forwardedconsistency

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

var Def = checkdef.MustParseCheckDefYAML("forwarded_consistency", checkYAML)

const (
	forwardedHeaderName = "Forwarded"
	legacyHeaderName    = "X-Forwarded-For"
)

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	result, err := probebase.ProbeWithHeaders(ctx, sctx, target.URL, map[string]string{
		forwardedHeaderName: `for="` + probebase.SpoofedForwardedMarker + `"`,
		legacyHeaderName:    probebase.SpoofedIPMarker,
	}, probebase.SpoofedForwardedMarker)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	if result.Err != nil {
		return harnessx.Result{Err: result.Err}, nil
	}

	forwardedBody, forwardedHeader := result.ReflectedInBody, result.ReflectedHeader
	forwardedReflected := forwardedBody || forwardedHeader != ""

	legacyBody, legacyHeader := probebase.FindMarker(result.Header, result.Body, probebase.SpoofedIPMarker)
	legacyReflected := legacyBody || legacyHeader != ""

	var observations []harnessx.Observation
	switch {
	case forwardedReflected && legacyReflected:
		observations = append(observations, harnessx.Observation{
			Title:       "Both Forwarded and X-Forwarded-For are trusted",
			Description: "Distinct spoofed values sent in RFC 7239 Forwarded and legacy X-Forwarded-For were both reflected back, so the proxy/origin doesn't normalize to a single authoritative client-IP source — a request can pick whichever header favors it.",
			Evidence:    "Forwarded reflected in " + describe(forwardedHeader) + "; X-Forwarded-For reflected in " + describe(legacyHeader),
		})
	case forwardedReflected != legacyReflected:
		observations = append(observations, harnessx.Observation{
			Title:       "Forwarded and X-Forwarded-For handling is inconsistent",
			Description: "Only one of RFC 7239 Forwarded and legacy X-Forwarded-For was reflected back for the same request, indicating inconsistent trust between the two header formats.",
			Evidence:    "Forwarded reflected: " + boolStr(forwardedReflected) + "; X-Forwarded-For reflected: " + boolStr(legacyReflected),
		})
	}

	return harnessx.Result{Observations: observations}, nil
})

func describe(headerName string) string {
	if headerName != "" {
		return "response header " + headerName
	}
	return "response body"
}

func boolStr(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
