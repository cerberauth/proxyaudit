// Package spoofedipbypass tests whether a proxy that does throttle keys its
// rate limit on a client-supplied header (X-Forwarded-For, X-Real-IP, ...)
// rather than the real transport peer. If it does, an attacker resets the
// limit at will by rotating a spoofed IP in that header, defeating the
// throttle entirely.
//
// It first drives a burst until the proxy throttles; if nothing throttles
// within the burst there is no limit to bypass and the check skips. Once
// throttled, it confirms a plain request is still being throttled, then
// sends a request carrying a fresh spoofed IP in each candidate header —
// a header that flips the response back to success is a confirmed bypass.
//
// Requires --aggressive: it sends a burst of requests, part of the opt-in
// attack-simulation suite.
package spoofedipbypass

import (
	"context"
	_ "embed"
	"fmt"
	"strconv"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/checks/ratelimit/rlprobe"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("spoofed_ip_bypass", checkYAML)

// spoofHeaders are the client-IP headers a misconfigured proxy may use as
// the rate-limit key instead of the transport peer address.
var spoofHeaders = []string{"X-Forwarded-For", "X-Real-IP", "True-Client-IP", "X-Client-IP", "X-Forwarded"}

// freshIP returns a distinct, routable-looking address for attempt n so
// each spoofed request looks like a different client.
func freshIP(n int) string {
	return fmt.Sprintf("198.51.100.%d", 1+n%250) // TEST-NET-2, non-routable but valid
}

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)
	if !sctx.Aggressive {
		return harnessx.Result{Skipped: true, SkipReason: "aggressive-suite check — rerun with --aggressive to send a rate-limit burst"}, nil
	}

	// Drive the proxy into throttling first; a slightly larger burst than
	// detection alone, to cross the limit reliably.
	statuses, err := rlprobe.Burst(ctx, sctx, target.URL, rlprobe.BurstSize+10)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	if !rlprobe.AnyThrottled(statuses) {
		return harnessx.Result{Skipped: true, SkipReason: "no throttling observed in a burst — no rate limit to bypass"}, nil
	}

	for i, h := range spoofHeaders {
		// Confirm the plain client is still throttled right now, so a
		// success under the spoofed header is attributable to the header,
		// not to the limit window having elapsed.
		plain, err := rlprobe.Get(ctx, sctx, target.URL, nil)
		if err != nil {
			return harnessx.Result{Err: err}, nil
		}
		if !rlprobe.Throttled(plain) {
			return harnessx.Result{Skipped: true, SkipReason: "throttle window elapsed before the bypass could be tested — rerun to retry"}, nil
		}

		ip := freshIP(i)
		spoofed, err := rlprobe.Get(ctx, sctx, target.URL, map[string]string{h: ip})
		if err != nil {
			return harnessx.Result{Err: err}, nil
		}
		if rlprobe.Throttled(spoofed) || spoofed == 0 {
			continue
		}
		return harnessx.Result{Observations: []harnessx.Observation{{
			Title:       "Rate limit bypassed via spoofed " + h,
			Description: "The proxy throttled a burst from this client (plain request still returns " + strconv.Itoa(plain) + "), but the same request carrying a spoofed " + h + ": " + ip + " was served normally (" + strconv.Itoa(spoofed) + "). The rate limit is keyed on the client-supplied " + h + " header rather than the real connection peer, so an attacker resets it at will by rotating that header — defeating the throttle.",
			Evidence:    "plain -> " + strconv.Itoa(plain) + "; " + h + ": " + ip + " -> " + strconv.Itoa(spoofed),
			Metadata:    map[string]string{"header": h, "plain_status": strconv.Itoa(plain), "spoofed_status": strconv.Itoa(spoofed)},
		}}}, nil
	}
	return harnessx.Result{}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
