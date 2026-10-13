// Package encodingbypass takes each baseline payload the WAF blocks in plain
// form and retries it with case variation, double URL-encoding, and
// Unicode fullwidth forms — encodings a backend commonly decodes or
// NFKC-normalizes back to the original string after the filter has already
// looked at (and waved through) the raw bytes.
//
// A variant getting through is a bypass candidate: whether it is
// exploitable depends on whether the backend decodes it, which a black-box
// scan can't tell.
package encodingbypass

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("encoding_bypass", checkYAML)

func status(r *probebase.FetchResult) string {
	return fmt.Sprintf("%d %s", r.StatusCode, http.StatusText(r.StatusCode))
}

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)
	param := probebase.WAFParamFor(target.URL)

	control, err := probebase.ProbeWAF(ctx, sctx, target.URL, probebase.QueryDelivery.Build(param, probebase.WAFBenignValue))
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	if !probebase.WAFControlUsable(control) {
		return harnessx.Result{Skipped: true, SkipReason: "benign control request failed or was itself rejected — cannot tell blocked payloads apart"}, nil
	}

	var observations []harnessx.Observation
	for _, p := range probebase.WAFPayloads {
		plain, err := probebase.ProbeWAF(ctx, sctx, target.URL, probebase.QueryDelivery.Build(param, p.Value))
		if err != nil {
			return harnessx.Result{Observations: observations, Err: err}, nil
		}
		// Nothing to bypass: baseline_payloads already reports a payload
		// that isn't blocked in plain form.
		if !probebase.WAFBlocked(control, plain) {
			continue
		}

		for _, variant := range probebase.EncodingVariants(param, p.Value) {
			result, err := probebase.ProbeWAF(ctx, sctx, target.URL, probebase.QueryRequest(variant.RawQuery))
			if err != nil {
				return harnessx.Result{Observations: observations, Err: err}, nil
			}
			if probebase.WAFBlocked(control, result) {
				continue
			}

			label := probebase.WAFCategoryLabel(p.Category)
			observations = append(observations, harnessx.Observation{
				Title:       label + " filter bypassed via " + variant.Technique,
				Description: "The " + label + " payload " + p.Value + " was blocked in plain form, but the same payload re-encoded with " + variant.Technique + " was passed through (" + status(result) + "). The filter inspects the raw request instead of what the backend will decode or normalize it to, so an attacker whose backend does that decoding can reach it with this encoding.",
				Evidence:    "GET ?" + param + "=" + p.Value + " -> " + status(plain) + "; GET ?" + variant.RawQuery + " -> " + status(result),
				Metadata:    map[string]string{"category": p.Category, "payload": p.Value, "technique": variant.Technique},
			})
			break
		}
	}
	return harnessx.Result{Observations: observations}, nil
})
