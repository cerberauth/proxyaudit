// Package nginxaliastraversal probes nginx-fingerprinted targets for the
// classic off-by-slash alias misconfiguration: a location directive
// without a trailing slash combined with an alias directive makes nginx
// strip only the literal prefix and append the remainder of the request
// path verbatim to the alias, so the location's prefix boundary can be
// stepped over without a "/" separator — and, from there, with "../" to
// escape the aliased directory entirely.
package nginxaliastraversal

import (
	"bytes"
	"context"
	_ "embed"
	"net/http"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("nginx_alias_traversal", checkYAML)

// candidatePrefixes are common alias-style location prefixes plausibly
// backed by an nginx `alias` directive.
var candidatePrefixes = []string{"/files", "/static", "/assets", "/media", "/public", "/uploads", "/download"}

// canaryFile is requested both under the prefix (as a well-formed request)
// and appended directly onto the prefix with no separator: if a location
// requires a trailing slash to match (the fixed configuration), the latter
// won't match the location at all and falls through to the default
// (non-200) response. If it matches and returns identical content (the
// off-by-slash bug), the location's prefix boundary isn't enforced, and an
// attacker can substitute a "../" traversal for the filename to escape the
// aliased directory.
const canaryFile = "index.html"

// skipUnlessNginx skips this check for targets that don't fingerprint as
// nginx via the Server header, since the off-by-slash alias bug is
// specific to nginx's prefix-based location matching.
var skipUnlessNginx = harnessx.SkipWhen(func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) string {
	fetched, ok := probebase.Fetch(store)
	if !ok || fetched.Err != nil {
		return "shared HTTP fetch failed — see probe.http_fetch"
	}
	if !strings.Contains(strings.ToLower(fetched.Header.Get("Server")), "nginx") {
		return "target does not fingerprint as nginx (Server header)"
	}
	return ""
})

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	var observations []harnessx.Observation
	for _, prefix := range candidatePrefixes {
		slashPath := prefix + "/" + canaryFile
		baseline, err := probebase.ProbePath(ctx, sctx, target.URL, slashPath)
		if err != nil {
			return harnessx.Result{Observations: observations, Err: err}, nil
		}
		if baseline.Err != nil || baseline.StatusCode != http.StatusOK || len(baseline.Body) == 0 {
			continue
		}

		offBySlashPath := prefix + canaryFile
		result, err := probebase.ProbePath(ctx, sctx, target.URL, offBySlashPath)
		if err != nil {
			return harnessx.Result{Observations: observations, Err: err}, nil
		}
		if result.Err != nil || result.StatusCode != http.StatusOK || !bytes.Equal(result.Body, baseline.Body) {
			continue
		}

		observations = append(observations, harnessx.Observation{
			Title:       "Nginx off-by-slash alias traversal at " + prefix,
			Description: "GET " + offBySlashPath + " — the location prefix " + prefix + " with no '/' separator before the filename — returned the same content as GET " + slashPath + ". This means the location matching " + prefix + " has no trailing slash, so nginx strips only the literal prefix and appends the remainder of the request path verbatim to the alias directory. An attacker can substitute a \"../\" traversal for the filename (e.g. " + prefix + "../) to escape the aliased directory and reach files outside it.",
			Evidence:    "GET " + slashPath + " -> " + http.StatusText(baseline.StatusCode) + "; GET " + offBySlashPath + " -> " + http.StatusText(result.StatusCode) + " (identical body)",
			Metadata:    map[string]string{"prefix": prefix, "off_by_slash_path": offBySlashPath},
		})
	}

	return harnessx.Result{Observations: observations}, nil
}, checkdef.WithSkip(skipUnlessNginx))
