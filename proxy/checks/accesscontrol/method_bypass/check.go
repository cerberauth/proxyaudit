// Package methodbypass probes a fixed list of common protected paths and,
// for any that deny a GET, retries the identical path with a different HTTP
// verb, testing whether the access control only gates the verb it expects
// rather than every verb the backend will route to the same handler.
package methodbypass

import (
	"context"
	_ "embed"
	"net/http"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("method_bypass", checkYAML)

// candidatePaths are common protected-path conventions that are plausibly
// gated only on the GET verb.
var candidatePaths = []string{"/admin", "/internal", "/private"}

// bypassMethods are the verbs an attacker would try once GET is denied:
// every other verb a router would still dispatch to the same handler.
// CONNECT and TRACE are excluded — they're rejected outright by most HTTP
// clients/servers and aren't representative of a routable API verb.
var bypassMethods = []string{
	http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions,
}

func denied(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

func granted(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	var observations []harnessx.Observation
	for _, path := range candidatePaths {
		baseline, err := probebase.ProbeRawPath(ctx, sctx, target.URL, http.MethodGet, path)
		if err != nil {
			return harnessx.Result{Observations: observations, Err: err}, nil
		}
		if baseline.Err != nil || !denied(baseline.StatusCode) {
			continue
		}

		for _, method := range bypassMethods {
			result, err := probebase.ProbeRawPath(ctx, sctx, target.URL, method, path)
			if err != nil {
				return harnessx.Result{Observations: observations, Err: err}, nil
			}
			if result.Err != nil || !granted(result.StatusCode) {
				continue
			}

			observations = append(observations, harnessx.Observation{
				Title:       "Access control bypassed via HTTP method at " + path,
				Description: "GET " + path + " was denied (" + http.StatusText(baseline.StatusCode) + "), but " + method + " " + path + " — the identical path, reached with a different verb — succeeded (" + http.StatusText(result.StatusCode) + "). The access control only gates the verb it expects instead of every verb the backend routes to this handler, letting an attacker reach it with a different method.",
				Evidence:    "GET " + path + " -> " + http.StatusText(baseline.StatusCode) + "; " + method + " " + path + " -> " + http.StatusText(result.StatusCode),
				Metadata:    map[string]string{"path": path, "method": method},
			})
			break
		}
	}

	return harnessx.Result{Observations: observations}, nil
})
