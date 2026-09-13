// Package verboseerrors triggers error responses via a nonexistent path and
// a malformed Range header, and inspects the bodies for stack traces,
// backend file paths, or internal hostnames.
package verboseerrors

import (
	"bytes"
	"context"
	_ "embed"
	"io"
	"net/http"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("verbose_errors", checkYAML)

// nonexistentPath is a distinctive, deterministic path unlikely to exist on
// a real deployment, used to trigger the target's default not-found/error
// handler.
const nonexistentPath = "/proxyaudit-nonexistent-check-2f8a1c"

// verboseMarkers are substrings that show up in stack traces, backend file
// paths, or internal hostnames leaked by common frameworks' default error
// pages.
var verboseMarkers = []string{
	"Traceback (most recent call last)",
	"Exception in thread",
	".java:",
	"System.Exception",
	"at System.",
	"Fatal error:",
	"Warning: ",
	"Whitelabel Error Page",
	"django.core",
	"/home/",
	"/var/www/",
	"/usr/local/",
	`C:\Users\`,
	`C:\inetpub\`,
}

func hasVerboseMarker(body []byte) (string, bool) {
	for _, m := range verboseMarkers {
		if bytes.Contains(body, []byte(m)) {
			return m, true
		}
	}
	return "", false
}

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	var observations []harnessx.Observation

	notFound, err := probebase.ProbePath(ctx, sctx, target.URL, nonexistentPath)
	if err == nil && notFound.Err == nil {
		if marker, found := hasVerboseMarker(notFound.Body); found {
			observations = append(observations, harnessx.Observation{
				Title:       "Not-found response leaks internal details",
				Description: "A request for a nonexistent path returned a body containing what looks like a stack trace, backend file path, or internal hostname instead of a generic error page.",
				Evidence:    "GET " + nonexistentPath + " matched marker: " + marker,
			})
		}
	}

	malformedRange, err := probeMalformedRange(ctx, sctx, target.URL)
	if err == nil && malformedRange != nil {
		if marker, found := hasVerboseMarker(malformedRange.Body); found {
			observations = append(observations, harnessx.Observation{
				Title:       "Malformed Range request leaks internal details",
				Description: "A request with a malformed Range header returned a body containing what looks like a stack trace, backend file path, or internal hostname.",
				Evidence:    "GET / with Range: bytes=abc-xyz matched marker: " + marker,
			})
		}
	}

	return harnessx.Result{Observations: observations}, nil
})

func probeMalformedRange(ctx context.Context, sctx *scanctx.ScanContext, baseURL string) (*probebase.PathResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Range", "bytes=abc-xyz")

	resp, err := sctx.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, probebase.MaxBodyBytes))
	return &probebase.PathResult{StatusCode: resp.StatusCode, Header: resp.Header, Body: body}, nil
}
