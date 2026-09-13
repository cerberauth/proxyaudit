// Package serverbanner checks whether the Server or X-Powered-By response
// headers disclose the proxy/backend software and, worse, its version.
package serverbanner

import (
	"context"
	_ "embed"
	"regexp"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("server_banner", checkYAML)

// versionPattern matches a dotted version number, e.g. "1.18.0" in
// "nginx/1.18.0" — its presence turns a mere software-name disclosure into
// a version disclosure, which is easier to match against known CVEs.
var versionPattern = regexp.MustCompile(`\d+\.\d+`)

var Check = checkdef.NewCheck(Def, func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	fetched, ok := probebase.Fetch(store)
	if !ok || fetched.Err != nil {
		return harnessx.Result{Err: probebase.ErrFetchUnavailable}, nil
	}

	var observations []harnessx.Observation

	if server := fetched.Header.Get("Server"); server != "" {
		title := "Server header discloses software name"
		if versionPattern.MatchString(server) {
			title = "Server header discloses software name and version"
		}
		observations = append(observations, harnessx.Observation{
			Title:       title,
			Description: "The Server response header identifies the fronting software" + versionNote(server) + ", helping an attacker target known vulnerabilities.",
			Evidence:    "Server: " + server,
		})
	}

	if poweredBy := fetched.Header.Get("X-Powered-By"); poweredBy != "" {
		observations = append(observations, harnessx.Observation{
			Title:       "X-Powered-By header discloses backend technology",
			Description: "The X-Powered-By response header identifies the backend technology, helping an attacker target known vulnerabilities.",
			Evidence:    "X-Powered-By: " + poweredBy,
		})
	}

	return harnessx.Result{Observations: observations}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))

func versionNote(server string) string {
	if versionPattern.MatchString(server) {
		return " and its version"
	}
	return ""
}
