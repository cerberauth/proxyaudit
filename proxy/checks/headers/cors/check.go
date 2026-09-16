// Package cors sends cross-origin requests carrying a spoofed Origin (an
// attacker-controlled marker origin, and the literal "null" origin) plus an
// OPTIONS preflight to a fixed list of common API paths, and inspects the
// Access-Control-* response headers a browser would act on directly — a
// reflected or wildcard Access-Control-Allow-Origin combined with
// Access-Control-Allow-Credentials: true, an accepted null origin, or a
// preflight cached for longer than any browser actually honors.
package cors

import (
	"context"
	_ "embed"
	"net/http"
	"strconv"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("cors", checkYAML)

// candidatePaths are the root plus common API/account endpoint conventions
// most likely to carry per-route CORS handling rather than the static
// headers a proxy applies to every response.
var candidatePaths = []string{"/", "/api", "/api/account", "/api/user", "/me"}

const (
	originHeader           = "Origin"
	allowOriginHeader      = "Access-Control-Allow-Origin"
	allowCredentialsHeader = "Access-Control-Allow-Credentials"
	maxAgeHeader           = "Access-Control-Max-Age"
	nullOrigin             = "null"
	pathMetadataKey        = "path"

	// maxReasonablePreflightCacheSeconds is the Chromium preflight-cache
	// ceiling (2h) — the tightest of the major browsers' caps (Firefox
	// caps at 24h). A server advertising a longer Access-Control-Max-Age
	// than any browser will actually honor is a sign the value wasn't
	// deliberately chosen.
	maxReasonablePreflightCacheSeconds = 7200
)

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	var observations []harnessx.Observation
	for _, path := range candidatePaths {
		resolved, err := probebase.ResolvePath(target.URL, path)
		if err != nil {
			return harnessx.Result{Observations: observations, Err: err}, nil
		}

		simple, err := probebase.ProbeCORS(ctx, sctx, resolved, http.MethodGet, map[string]string{originHeader: probebase.CORSOriginMarker})
		if err != nil {
			return harnessx.Result{Observations: observations, Err: err}, nil
		}
		if simple.Err == nil {
			observations = append(observations, credentialedOriginObservations(path, simple)...)
		}

		nullResult, err := probebase.ProbeCORS(ctx, sctx, resolved, http.MethodGet, map[string]string{originHeader: nullOrigin})
		if err != nil {
			return harnessx.Result{Observations: observations, Err: err}, nil
		}
		if nullResult.Err == nil && nullResult.Header.Get(allowOriginHeader) == nullOrigin {
			observations = append(observations, harnessx.Observation{
				Title:       "CORS accepts the null origin: " + path,
				Description: "The response to a request with Origin: null returned Access-Control-Allow-Origin: null, allowing any sandboxed iframe or file:// page (which browsers send with the literal Origin: null) to make credentialed cross-origin requests.",
				Evidence:    "GET " + path + " with Origin: null -> " + allowOriginHeader + ": " + nullResult.Header.Get(allowOriginHeader),
				Metadata:    map[string]string{pathMetadataKey: path},
			})
		}

		preflight, err := probebase.ProbeCORS(ctx, sctx, resolved, http.MethodOptions, map[string]string{
			originHeader:                     probebase.CORSOriginMarker,
			"Access-Control-Request-Method":  http.MethodPut,
			"Access-Control-Request-Headers": "X-Requested-With",
		})
		if err != nil {
			return harnessx.Result{Observations: observations, Err: err}, nil
		}
		if preflight.Err == nil {
			observations = append(observations, preflightObservations(path, preflight)...)
		}
	}

	return harnessx.Result{Observations: observations}, nil
})

// credentialedOriginObservations flags a reflected (exact) or wildcard
// Access-Control-Allow-Origin combined with Access-Control-Allow-Credentials:
// true, tested separately since browsers treat them differently (a
// credentialed request only succeeds against a reflected origin, never a
// literal wildcard) but both are server-side misconfigurations.
func credentialedOriginObservations(path string, result *probebase.CORSResult) []harnessx.Observation {
	acao := result.Header.Get(allowOriginHeader)
	acac := result.Header.Get(allowCredentialsHeader)
	if acac != "true" || acao == "" {
		return nil
	}

	if acao == probebase.CORSOriginMarker {
		return []harnessx.Observation{{
			Title:       "Reflected Origin combined with credentialed CORS response: " + path,
			Description: "The response reflected an attacker-controlled Origin back in Access-Control-Allow-Origin and set Access-Control-Allow-Credentials: true, letting any site read this endpoint's authenticated response in a victim's browser.",
			Evidence:    "GET " + path + " with Origin: " + probebase.CORSOriginMarker + " -> " + allowOriginHeader + ": " + acao + "; " + allowCredentialsHeader + ": " + acac,
			Metadata:    map[string]string{pathMetadataKey: path},
		}}
	}
	if acao == "*" {
		return []harnessx.Observation{{
			Title:       "Wildcard Access-Control-Allow-Origin combined with Access-Control-Allow-Credentials: " + path,
			Description: "The response set Access-Control-Allow-Origin: * together with Access-Control-Allow-Credentials: true. Browsers reject this exact combination for credentialed requests, but a server sending it is still misconfigured and may serve a properly reflected origin to a client that omits the wildcard check.",
			Evidence:    "GET " + path + " -> " + allowOriginHeader + ": *; " + allowCredentialsHeader + ": " + acac,
			Metadata:    map[string]string{pathMetadataKey: path},
		}}
	}
	return nil
}

// preflightObservations flags an OPTIONS preflight that grants credentialed
// access to an arbitrary origin, and/or caches that grant (Access-Control-
// Max-Age) for longer than any browser actually honors.
func preflightObservations(path string, result *probebase.CORSResult) []harnessx.Observation {
	var observations []harnessx.Observation

	acao := result.Header.Get(allowOriginHeader)
	acac := result.Header.Get(allowCredentialsHeader)
	if acac == "true" && (acao == probebase.CORSOriginMarker || acao == "*") {
		observations = append(observations, harnessx.Observation{
			Title:       "CORS preflight allows credentialed requests from an arbitrary origin: " + path,
			Description: "The OPTIONS preflight response granted Access-Control-Allow-Credentials: true for an attacker-controlled/wildcard Access-Control-Allow-Origin, so the browser will proceed to send the credentialed actual request.",
			Evidence:    "OPTIONS " + path + " with Origin: " + probebase.CORSOriginMarker + " -> " + allowOriginHeader + ": " + acao + "; " + allowCredentialsHeader + ": " + acac,
			Metadata:    map[string]string{pathMetadataKey: path},
		})
	}

	if maxAge, ok := parseMaxAge(result.Header.Get(maxAgeHeader)); ok && maxAge > maxReasonablePreflightCacheSeconds {
		observations = append(observations, harnessx.Observation{
			Title:       "CORS preflight cache duration exceeds browser ceiling: " + path,
			Description: "The OPTIONS preflight response set Access-Control-Max-Age beyond what any major browser actually caches a preflight for, a sign the value wasn't deliberately tuned — and, combined with a permissive preflight, extends how long a since-revoked grant stays cached client-side.",
			Evidence:    "OPTIONS " + path + " -> " + maxAgeHeader + ": " + result.Header.Get(maxAgeHeader) + "s",
			Metadata:    map[string]string{pathMetadataKey: path},
		})
	}

	return observations
}

func parseMaxAge(raw string) (int, bool) {
	if raw == "" {
		return 0, false
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, false
	}
	return n, true
}
