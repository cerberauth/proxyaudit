// Package hsts checks for the presence of Strict-Transport-Security and
// sane includeSubDomains, preload, and max-age directives.
package hsts

import (
	"context"
	_ "embed"
	"strconv"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("hsts", checkYAML)

const headerName = "Strict-Transport-Security"

// MinSaneMaxAge is the commonly recommended minimum max-age (180 days) for
// an HSTS policy to meaningfully protect visitors between renewals.
const MinSaneMaxAge = 180 * 24 * 60 * 60

var Check = checkdef.NewCheck(Def, func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	fetched, ok := probebase.Fetch(store)
	if !ok || fetched.Err != nil {
		return harnessx.Result{Err: probebase.ErrFetchUnavailable}, nil
	}

	value := fetched.Header.Get(headerName)
	if value == "" {
		return harnessx.Result{Observations: []harnessx.Observation{{
			Title:       "Strict-Transport-Security header is missing",
			Description: "The response does not include a Strict-Transport-Security header, so browsers cannot enforce HTTPS-only access to this host.",
			Evidence:    "no " + headerName + " header in response",
		}}}, nil
	}

	directives := parseDirectives(value)

	var observations []harnessx.Observation

	maxAge, hasMaxAge := directives["max-age"]
	maxAgeSeconds, _ := strconv.Atoi(maxAge)
	if !hasMaxAge || maxAgeSeconds < MinSaneMaxAge {
		observations = append(observations, harnessx.Observation{
			Title:       "Strict-Transport-Security max-age is too low",
			Description: "The HSTS max-age directive is missing or below the recommended 180-day minimum, so the policy expires too quickly to protect returning visitors.",
			Evidence:    headerName + ": " + value,
			Metadata:    map[string]string{"max_age": maxAge},
		})
	}

	if _, ok := directives["includesubdomains"]; !ok {
		observations = append(observations, harnessx.Observation{
			Title:       "Strict-Transport-Security missing includeSubDomains",
			Description: "The HSTS policy does not set includeSubDomains, leaving subdomains unprotected from protocol downgrade attacks.",
			Evidence:    headerName + ": " + value,
		})
	}

	if _, ok := directives["preload"]; !ok {
		observations = append(observations, harnessx.Observation{
			Title:       "Strict-Transport-Security missing preload",
			Description: "The HSTS policy does not set preload. This is optional but, combined with browser HSTS-preload-list submission, removes the unprotected first request entirely.",
			Evidence:    headerName + ": " + value,
		})
	}

	return harnessx.Result{Observations: observations}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))

func parseDirectives(value string) map[string]string {
	directives := make(map[string]string)
	for _, part := range strings.Split(value, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		name, val, _ := strings.Cut(part, "=")
		directives[strings.ToLower(strings.TrimSpace(name))] = strings.TrimSpace(val)
	}
	return directives
}
