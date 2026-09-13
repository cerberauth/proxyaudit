// Package cookieflags checks every Set-Cookie header in the response for
// the Secure, HttpOnly, and SameSite attributes.
package cookieflags

import (
	"context"
	_ "embed"
	"net/http"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("cookie_flags", checkYAML)

var Check = checkdef.NewCheck(Def, func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	fetched, ok := probebase.Fetch(store)
	if !ok || fetched.Err != nil {
		return harnessx.Result{Err: probebase.ErrFetchUnavailable}, nil
	}

	cookies := (&http.Response{Header: fetched.Header}).Cookies()

	var observations []harnessx.Observation
	for _, c := range cookies {
		var missing []string
		if !c.Secure {
			missing = append(missing, "Secure")
		}
		if !c.HttpOnly {
			missing = append(missing, "HttpOnly")
		}
		if c.SameSite == http.SameSiteDefaultMode {
			missing = append(missing, "SameSite")
		}
		if len(missing) == 0 {
			continue
		}
		observations = append(observations, harnessx.Observation{
			Title:       "Cookie missing security attributes: " + c.Name,
			Description: "The response sets a cookie without one or more of the Secure, HttpOnly, and SameSite attributes, increasing its exposure to interception, script access, or cross-site request forgery.",
			Evidence:    "Set-Cookie: " + c.Name + " (missing: " + joinComma(missing) + ")",
			Metadata:    map[string]string{"cookie_name": c.Name},
		})
	}

	return harnessx.Result{Observations: observations}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))

func joinComma(items []string) string {
	out := ""
	for i, s := range items {
		if i > 0 {
			out += ", "
		}
		out += s
	}
	return out
}
