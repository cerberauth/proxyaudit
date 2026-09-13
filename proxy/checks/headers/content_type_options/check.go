// Package contenttypeoptions checks for X-Content-Type-Options: nosniff.
package contenttypeoptions

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

var Def = checkdef.MustParseCheckDefYAML("content_type_options", checkYAML)

const headerName = "X-Content-Type-Options"

var Check = checkdef.NewCheck(Def, func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	fetched, ok := probebase.Fetch(store)
	if !ok || fetched.Err != nil {
		return harnessx.Result{Err: probebase.ErrFetchUnavailable}, nil
	}

	if strings.EqualFold(strings.TrimSpace(fetched.Header.Get(headerName)), "nosniff") {
		return harnessx.Result{}, nil
	}

	return harnessx.Result{Observations: []harnessx.Observation{{
		Title:       headerName + " header is missing or not set to nosniff",
		Description: "The response does not set X-Content-Type-Options: nosniff, allowing browsers to MIME-sniff the response into an unintended, potentially executable content type.",
		Evidence:    headerName + ": " + fetched.Header.Get(headerName),
	}}}, nil
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
