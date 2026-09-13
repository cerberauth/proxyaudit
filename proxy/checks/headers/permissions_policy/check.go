// Package permissionspolicy checks for the presence of a Permissions-Policy
// header.
package permissionspolicy

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("permissions_policy", checkYAML)

const headerName = "Permissions-Policy"

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
		Description: "The response does not include a Permissions-Policy header, so browsers apply their default (often permissive) policy for powerful features like camera, microphone, and geolocation.",
		Evidence:    "no " + headerName + " header in response",
	}}}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
