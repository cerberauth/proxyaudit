// Package cachepoisoning adapts cache-detective's
// cache/checks/security.UnkeyedHeaderCheck: injects a marker via a header
// commonly left out of the cache key (X-Forwarded-Host, X-Forwarded-
// Scheme, X-Original-URL, X-Rewrite-URL) and checks whether a follow-up
// plain request receives the poisoned response — classic web cache
// poisoning.
//
// Requires --aggressive: cache-detective's check itself gates on
// ProbeCtx.Aggressive (checked inline rather than via harnessx.Skip, so a
// non-aggressive run reports no finding at all rather than a misleading
// skip entry — see cache-detective's own security package for why), which
// proxyaudit's adapt.ProbeCtx threads through from ScanContext.Aggressive.
package cachepoisoning

import (
	"context"
	_ "embed"

	"github.com/cerberauth/cache-detective/cache/checks/security"
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/checks/caching/adapt"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("cache_poisoning", checkYAML)

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	return adapt.Run(ctx, target, security.UnkeyedHeaderCheck, nil)
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
