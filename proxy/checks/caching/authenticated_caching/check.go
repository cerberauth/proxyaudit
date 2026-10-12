// Package authenticatedcaching adapts cache-detective's
// cache/checks/cacheability.Check and .AuthCheck as a single proxyaudit
// check: sends a request carrying synthetic credentials (a bearer token
// and a cookie) and flags a response that's cacheable per RFC 9111 §3.5
// without one of that section's opt-in directives (must-revalidate,
// public, s-maxage) — a shared cache in front of the origin isn't
// supposed to store a response to a request carrying Authorization
// otherwise. Severity is compounded in the finding when the response body
// or Set-Cookie header carries PII, tokens, or session data, per
// cache-detective's own detection.
package authenticatedcaching

import (
	"context"
	_ "embed"

	cdcheckbase "github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/cache-detective/cache/checks/cacheability"
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/checks/caching/adapt"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("authenticated_caching", checkYAML)

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	// cacheability.AuthCheck reads cacheability.Check's stored analysis
	// (Result.Data) via store.GetForResource, per cache-detective's own
	// dependency chain — cacheability.Check runs first here for that
	// reason, not to duplicate its logic.
	cacheabilityResult, err := adapt.Run(ctx, target, cacheability.Check, nil)
	if err != nil || cacheabilityResult.Err != nil {
		return cacheabilityResult, err
	}

	return adapt.Run(ctx, target, cacheability.AuthCheck, map[harnessx.CheckID]harnessx.Result{
		cdcheckbase.CheckIDCacheability: cacheabilityResult,
	})
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
