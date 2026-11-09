// Package missingthrottling sends a small, bounded burst of requests and
// reports when none of them is throttled — the proxy enforces no per-client
// request rate limit of its own, so a single client can drive unbounded
// load straight through to the backend.
//
// The finding is informational-to-low: many deployments rate-limit at the
// backend or an external layer instead, which a black-box burst from one
// client cannot see. It flags only the observable fact that the proxy
// itself did not throttle a rapid burst.
//
// Requires --aggressive: it sends a burst of requests, part of the opt-in
// attack-simulation suite.
package missingthrottling

import (
	"context"
	_ "embed"
	"strconv"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/checks/ratelimit/rlprobe"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("missing_throttling", checkYAML)

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)
	if !sctx.Aggressive {
		return harnessx.Result{Skipped: true, SkipReason: "aggressive-suite check — rerun with --aggressive to send a rate-limit burst"}, nil
	}

	statuses, err := rlprobe.Burst(ctx, sctx, target.URL, rlprobe.BurstSize)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	if rlprobe.AnyThrottled(statuses) {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Observations: []harnessx.Observation{{
		Title:       "Proxy enforces no per-client request throttling",
		Description: "A burst of " + strconv.Itoa(len(statuses)) + " requests from a single client was served without any being rate-limited (no 429 or 503). The proxy applies no per-client throttling of its own, so one client can drive unbounded request load through to the backend. If rate limiting exists only at the backend or an external layer, it is not visible here and may not protect the backend from pre-auth floods.",
		Evidence:    strconv.Itoa(len(statuses)) + " consecutive requests, none throttled (last status " + strconv.Itoa(statuses[len(statuses)-1]) + ")",
		Metadata:    map[string]string{"requests": strconv.Itoa(len(statuses))},
	}}}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
