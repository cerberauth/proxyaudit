// Package cachedeception adapts cache-detective's
// cache/checks/security.CacheDeceptionCheck: appends a static-file
// extension or nonexistent sub-path to the target's own path and checks
// whether the (potentially authenticated) origin response gets served
// identically — and looks cacheable — under that path.
//
// Requires --aggressive: cache-detective's check itself gates on
// ProbeCtx.Aggressive (checked inline rather than via harnessx.Skip — see
// cache-detective's own security package for why), which proxyaudit's
// adapt.ProbeCtx threads through from ScanContext.Aggressive.
package cachedeception

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

var Def = checkdef.MustParseCheckDefYAML("cache_deception", checkYAML)

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	return adapt.Run(ctx, target, security.CacheDeceptionCheck, nil)
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
