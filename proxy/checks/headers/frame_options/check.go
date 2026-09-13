// Package frameoptions checks for X-Frame-Options or a CSP frame-ancestors
// directive that would prevent the response from being framed.
package frameoptions

import (
	"context"
	_ "embed"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("frame_options", checkYAML)

var Check = checkdef.NewCheck(Def, func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	fetched, ok := probebase.Fetch(store)
	if !ok || fetched.Err != nil {
		return harnessx.Result{Err: probebase.ErrFetchUnavailable}, nil
	}

	if fetched.Header.Get("X-Frame-Options") != "" {
		return harnessx.Result{}, nil
	}
	if strings.Contains(fetched.Header.Get("Content-Security-Policy"), "frame-ancestors") {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Observations: []harnessx.Observation{{
		Title:       "No clickjacking protection",
		Description: "The response sets neither X-Frame-Options nor a CSP frame-ancestors directive, so it can be embedded in a frame on an attacker-controlled page.",
		Evidence:    "no X-Frame-Options header and no frame-ancestors CSP directive in response",
	}}}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
