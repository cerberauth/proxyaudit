// Package varyconsistency adapts cache-detective's
// cache/checks/varykey.Check: probes whether Accept-Encoding,
// Accept-Language, User-Agent, and a custom header actually change the
// response, and compares that against the response's declared Vary
// header — flagging both an input that changes the response but isn't
// declared (a cache-poisoning surface) and a declared input with no
// observed effect (wasted cache fragmentation).
package varyconsistency

import (
	"context"
	_ "embed"

	"github.com/cerberauth/cache-detective/cache/checks/varykey"
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/checks/caching/adapt"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("vary_consistency", checkYAML)

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	return adapt.Run(ctx, target, varykey.Check, nil)
}, checkdef.WithSkip(probebase.SkipUnlessFetched))
