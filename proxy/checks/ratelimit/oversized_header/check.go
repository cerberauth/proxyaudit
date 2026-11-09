// Package oversizedheader tests whether the proxy caps request header size.
// A front-end that forwards an arbitrarily large header set (rather than
// rejecting it with 431/400/413) lets a client force large per-request
// allocations on the proxy and backend — a cheap memory-pressure / DoS
// vector, and often a sign the proxy isn't buffering defensively.
//
// It sends one request carrying a single very large (128 KiB) header,
// well above typical proxy limits (nginx 8 KiB, Apache ~8 KiB) but bounded,
// and flags acceptance. It confirms an ordinary request is accepted first,
// so a target that rejects everything isn't misread.
//
// Requires --aggressive: it sends a deliberately oversized request, part of
// the opt-in attack-simulation suite.
package oversizedheader

import (
	"context"
	_ "embed"
	"strconv"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/checks/ratelimit/rlprobe"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("oversized_header", checkYAML)

// headerBytes is the size of the single oversized header value — above
// common proxy caps, far below anything that could itself exhaust memory.
const headerBytes = 128 * 1024

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)
	if !sctx.Aggressive {
		return harnessx.Result{Skipped: true, SkipReason: "aggressive-suite check — rerun with --aggressive to send an oversized request"}, nil
	}

	control, err := rlprobe.Get(ctx, sctx, target.URL, nil)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	if control == 0 || control >= 400 {
		return harnessx.Result{Skipped: true, SkipReason: "ordinary request not accepted (status " + strconv.Itoa(control) + ") — can't tell an oversize rejection from a blanket one"}, nil
	}

	oversized, err := rlprobe.Get(ctx, sctx, target.URL, map[string]string{
		"X-Proxyaudit-Pad": strings.Repeat("A", headerBytes),
	})
	if err != nil {
		// A transport-level refusal (connection reset/closed) is the proxy
		// rejecting the oversized request — the desired behaviour.
		return harnessx.Result{}, nil
	}
	// Rejected with a status: 431/400/413/414 (or any 4xx/5xx) is correct
	// defensive handling.
	if oversized == 0 || oversized >= 400 {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Observations: []harnessx.Observation{{
		Title:       "Proxy accepts oversized request headers without a limit",
		Description: "A request carrying a single " + strconv.Itoa(headerBytes/1024) + " KiB header was accepted (" + strconv.Itoa(oversized) + ") instead of being rejected with 431/400/413. The proxy enforces no request-header size cap, so a client can force large per-request allocations on the proxy and backend — a low-cost memory-pressure / denial-of-service vector.",
		Evidence:    strconv.Itoa(headerBytes/1024) + " KiB header -> " + strconv.Itoa(oversized) + "; ordinary request -> " + strconv.Itoa(control),
		Metadata:    map[string]string{"header_bytes": strconv.Itoa(headerBytes), "status": strconv.Itoa(oversized)},
	}}}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
