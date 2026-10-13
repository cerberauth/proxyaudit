// Package baselinepayloads sends a baseline set of textbook SQL injection,
// cross-site scripting, and path traversal payloads and checks that a WAF
// or filtering layer in front of the backend blocks them, rather than
// passing them through. A payload counts as blocked when the response
// differs from a benign control request's with a rejection status (or the
// connection is dropped).
package baselinepayloads

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

var Def = checkdef.MustParseCheckDefYAML("baseline_payloads", checkYAML)

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

	var categories []string
	passed := map[string][]string{} // category -> evidence of each payload passed through
	blockedAny := false
	for _, p := range probebase.WAFPayloads {
		result, err := probebase.ProbeWAF(ctx, sctx, target.URL, probebase.QueryDelivery.Build(param, p.Value))
		if err != nil {
			return harnessx.Result{Err: err}, nil
		}
		if probebase.WAFBlocked(control, result) {
			blockedAny = true
			continue
		}
		if _, ok := passed[p.Category]; !ok {
			categories = append(categories, p.Category)
		}
		passed[p.Category] = append(passed[p.Category], fmt.Sprintf("%s -> %s", p.Value, status(result)))
	}

	var observations []harnessx.Observation
	for _, category := range categories {
		label := probebase.WAFCategoryLabel(category)
		description := label + " payloads sent as a query parameter were passed through to the backend instead of being blocked (the benign control request returned " + status(control) + ", and so did the payload)."
		if blockedAny {
			description += " Other payloads were blocked, so a filtering layer is present but its coverage of this attack class is incomplete."
		} else {
			description += " No baseline payload of any category was blocked, so no WAF or request filtering appears to be in front of the backend."
		}
		observations = append(observations, harnessx.Observation{
			Title:       label + " payload not blocked",
			Description: description,
			Evidence:    "GET ?" + param + "=<payload>: " + strings.Join(passed[category], "; "),
			Metadata:    map[string]string{"category": category},
		})
	}
	return harnessx.Result{Observations: observations}, nil
})
