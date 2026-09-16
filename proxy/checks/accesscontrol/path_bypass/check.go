// Package pathbypass probes a fixed list of common protected paths and, for
// any that deny access, retries case/encoding/traversal variants of the
// same path that a backend commonly normalizes away, testing whether a
// naive prefix-based access control (matching on the raw, unnormalized
// path) can be bypassed by a differently-formatted request that still
// resolves to the protected resource.
package pathbypass

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("path_bypass", checkYAML)

// candidatePaths are common protected-path conventions that are plausibly
// gated by a prefix match on the raw request path.
var candidatePaths = []string{"/admin", "/internal", "/private"}

func denied(status int) bool {
	return status == http.StatusUnauthorized || status == http.StatusForbidden
}

func granted(status int) bool {
	return status >= http.StatusOK && status < http.StatusMultipleChoices
}

// bypassVariants returns path-normalization bypass candidates for path
// (case variation, duplicate/trailing slash, trailing dot segment, encoded
// traversal, double-encoding, null byte, and a matrix/semicolon parameter)
// — the permutation classes named in
// https://github.com/laluka/bypass-url-parser applied to a single path
// rather than that tool's full combinatorial payload set. Every entry was
// verified against the api-vulns-challenges proxy-path-bypass fixture to
// grant access in vulnerable mode without also granting it in fixed mode;
// dot-segment traversal (e.g. "/%2e%2e"+path) was dropped for the opposite
// reason — that fixture's "fixed" normalization doesn't resolve it either,
// which would make it a false positive.
func bypassVariants(path string) []string {
	trimmed := strings.TrimPrefix(path, "/")
	return []string{
		"/" + strings.ToUpper(trimmed), // case variation: /ADMIN
		"/" + path,                     // duplicate leading slash: //admin
		path + "/",                     // trailing slash: /admin/
		path + "/.",                    // trailing dot segment: /admin/.
		path + "%2f.." + path,          // partially-encoded traversal back to itself: /admin%2f../admin
		fmt.Sprintf("/%%25%02X%s", trimmed[0], trimmed[1:]), // double-encoded first byte: /%2561dmin
		path + "%00",  // null byte suffix: /admin%00
		path + ";x=y", // matrix/semicolon parameter: /admin;x=y
	}
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

		for _, variant := range bypassVariants(path) {
			result, err := probebase.ProbeRawPath(ctx, sctx, target.URL, http.MethodGet, variant)
			if err != nil {
				return harnessx.Result{Observations: observations, Err: err}, nil
			}
			if result.Err != nil || !granted(result.StatusCode) {
				continue
			}

			observations = append(observations, harnessx.Observation{
				Title:       "Access control bypassed via path normalization at " + path,
				Description: "GET " + path + " was denied (" + http.StatusText(baseline.StatusCode) + "), but GET " + variant + " — a case/encoding/traversal variant of the same path that a backend commonly normalizes away — succeeded (" + http.StatusText(result.StatusCode) + "). The access control is matching on the raw, unnormalized path instead of the path the backend will actually resolve, letting an attacker reach this endpoint with a differently-formatted request.",
				Evidence:    "GET " + path + " -> " + http.StatusText(baseline.StatusCode) + "; GET " + variant + " -> " + http.StatusText(result.StatusCode),
				Metadata:    map[string]string{"path": path, "bypass_path": variant},
			})
			break
		}
	}

	return harnessx.Result{Observations: observations}, nil
})
