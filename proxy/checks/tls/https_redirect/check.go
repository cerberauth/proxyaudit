// Package httpsredirect checks whether a plain-HTTP request to the target
// is redirected to HTTPS.
package httpsredirect

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"net/url"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("https_redirect", checkYAML)

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	u, err := url.Parse(target.URL)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	if u.Scheme != "https" {
		return harnessx.Result{Skipped: true, SkipReason: "target is not HTTPS"}, nil
	}

	httpURL := *u
	httpURL.Scheme = "http"

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, httpURL.String(), nil)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}

	client := &http.Client{
		Transport: sctx.HTTPClient.Transport,
		Timeout:   sctx.HTTPClient.Timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		// Plain HTTP not served at all is not itself an HTTPS-redirect
		// failure — nothing to redirect.
		return harnessx.Result{}, nil
	}
	defer resp.Body.Close()

	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return harnessx.Result{Observations: []harnessx.Observation{{
			Title:       "Plain HTTP request is not redirected to HTTPS",
			Description: "A plain-HTTP request to the target received a non-redirect response instead of being redirected to HTTPS, allowing traffic to be sent (and intercepted) unencrypted.",
			Evidence:    fmt.Sprintf("GET %s -> %d", httpURL.String(), resp.StatusCode),
		}}}, nil
	}

	location := resp.Header.Get("Location")
	loc, err := url.Parse(location)
	if err != nil || loc.Scheme != "https" {
		return harnessx.Result{Observations: []harnessx.Observation{{
			Title:       "HTTP redirect does not point to HTTPS",
			Description: "A plain-HTTP request to the target was redirected, but not to an https:// URL.",
			Evidence:    "Location: " + location,
		}}}, nil
	}

	return harnessx.Result{}, nil
})
