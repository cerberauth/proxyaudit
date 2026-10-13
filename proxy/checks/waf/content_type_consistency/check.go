// Package contenttypeconsistency delivers each baseline payload in the
// query string and in form, JSON, multipart, plain-text, and gzip-encoded
// request bodies, and flags a payload that is blocked in one delivery but
// passed in another. A WAF that only parses the content types and
// encodings it was configured for leaves the rest uninspected.
package contenttypeconsistency

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

var Def = checkdef.MustParseCheckDefYAML("content_type_consistency", checkYAML)

func status(r *probebase.FetchResult) string {
	return fmt.Sprintf("%d %s", r.StatusCode, http.StatusText(r.StatusCode))
}

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)
	param := probebase.WAFParamFor(target.URL)

	// Each delivery needs its own benign control: a body POSTed to a path
	// that only serves GET may answer differently from a query string.
	var deliveries []probebase.WAFDelivery
	var controls []*probebase.FetchResult
	for _, d := range probebase.WAFDeliveries {
		control, err := probebase.ProbeWAF(ctx, sctx, target.URL, d.Build(param, probebase.WAFBenignValue))
		if err != nil {
			return harnessx.Result{Err: err}, nil
		}
		if probebase.WAFControlUsable(control) {
			deliveries = append(deliveries, d)
			controls = append(controls, control)
		}
	}
	if len(deliveries) < 2 {
		return harnessx.Result{Skipped: true, SkipReason: "fewer than two content types/encodings accepted a benign control request — nothing to compare"}, nil
	}

	var observations []harnessx.Observation
	for _, p := range probebase.WAFPayloads {
		var blocked, passed []string
		var evidence []string
		for i, d := range deliveries {
			result, err := probebase.ProbeWAF(ctx, sctx, target.URL, d.Build(param, p.Value))
			if err != nil {
				return harnessx.Result{Observations: observations, Err: err}, nil
			}
			if probebase.WAFBlocked(controls[i], result) {
				blocked = append(blocked, d.Name)
			} else {
				passed = append(passed, d.Name)
			}
			evidence = append(evidence, d.Name+" -> "+status(result))
		}
		if len(blocked) == 0 || len(passed) == 0 {
			continue
		}

		label := probebase.WAFCategoryLabel(p.Category)
		observations = append(observations, harnessx.Observation{
			Title:       label + " filtering depends on content type",
			Description: "The " + label + " payload " + p.Value + " was blocked when delivered as " + strings.Join(blocked, ", ") + ", but passed through when delivered as " + strings.Join(passed, ", ") + ". The filter only inspects the content types and encodings it parses, so an attacker can simply choose one it skips.",
			Evidence:    strings.Join(evidence, "; "),
			Metadata: map[string]string{
				"category": p.Category,
				"payload":  p.Value,
				"blocked":  strings.Join(blocked, ", "),
				"passed":   strings.Join(passed, ", "),
			},
		})
	}
	return harnessx.Result{Observations: observations}, nil
})
