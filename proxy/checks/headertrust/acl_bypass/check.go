// Package aclbypass probes a fixed list of common internal/admin paths and
// compares the response with and without a spoofed loopback client-IP
// header, testing whether the same client-supplied X-Forwarded-For/
// X-Real-IP headers other headertrust checks show are merely reflected can
// also flip an access-control decision — the downstream ACL/rate-limit
// bypass the reflection-based checks can only hint at.
package aclbypass

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

var Def = checkdef.MustParseCheckDefYAML("acl_bypass", checkYAML)

// candidatePaths are common internal/admin path conventions that are
// plausibly gated on the caller's IP address.
var candidatePaths = []string{
	"/internal", "/internal/admin", "/internal/api", "/admin/internal", "/private",
}

// spoofedLoopbackIPs are the values an attacker would try first: the
// loopback addresses an IP-based ACL commonly trusts as "internal".
var spoofedLoopbackIPs = []string{"127.0.0.1", "::1"}

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
		baseline, err := probebase.ProbePath(ctx, sctx, target.URL, path)
		if err != nil {
			return harnessx.Result{Observations: observations, Err: err}, nil
		}
		if baseline.Err != nil || !denied(baseline.StatusCode) {
			continue
		}

		for _, ip := range spoofedLoopbackIPs {
			spoofed, err := probebase.ProbePathWithHeaders(ctx, sctx, target.URL, path, map[string]string{
				"X-Forwarded-For": ip,
				"X-Real-IP":       ip,
			})
			if err != nil {
				return harnessx.Result{Observations: observations, Err: err}, nil
			}
			if spoofed.Err != nil || !granted(spoofed.StatusCode) {
				continue
			}

			observations = append(observations, harnessx.Observation{
				Title:       "IP-based access control bypassed via spoofed client-IP header at " + path,
				Description: "GET " + path + " was denied (" + http.StatusText(baseline.StatusCode) + ") without a client-IP header, but succeeded (" + http.StatusText(spoofed.StatusCode) + ") once a spoofed loopback X-Forwarded-For/X-Real-IP header was sent — the access control trusts the client-supplied header instead of the real connection address, letting an attacker reach this endpoint or bypass a downstream rate limit keyed on the same header.",
				Evidence:    "GET " + path + " -> " + http.StatusText(baseline.StatusCode) + "; GET " + path + " with X-Forwarded-For/X-Real-IP: " + ip + " -> " + http.StatusText(spoofed.StatusCode),
				Metadata:    map[string]string{"path": path, "spoofed_ip": ip},
			})
			break
		}
	}

	return harnessx.Result{Observations: observations}, nil
})
