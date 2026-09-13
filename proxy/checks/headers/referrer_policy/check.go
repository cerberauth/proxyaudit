// Package referrerpolicy checks for the presence of a Referrer-Policy
// header.
package referrerpolicy

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("referrer_policy", checkYAML)

const headerName = "Referrer-Policy"

var Check = checkdef.NewCheck(Def, func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	fetched, ok := probebase.Fetch(store)
	if !ok || fetched.Err != nil {
		return harnessx.Result{Err: probebase.ErrFetchUnavailable}, nil
	}

	if fetched.Header.Get(headerName) != "" {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Observations: []harnessx.Observation{{
		Title:       headerName + " header is missing",
		Description: "The response does not include a Referrer-Policy header, so browsers fall back to their default (often permissive) referrer behavior, potentially leaking the full request URL to third parties.",
		Evidence:    "no " + headerName + " header in response",
	}}}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
