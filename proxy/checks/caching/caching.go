// Package caching runs cache-detective's check pack against the single URL
// proxyaudit scans, through harnessx/embed, under proxyaudit's own check IDs
// and definitions.
package caching

import (
	"context"
	"net/http"
	"time"

	cache "github.com/cerberauth/cache-detective/cache"
	cdcheckbase "github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/harnessx/embed"
	"github.com/cerberauth/harnessx/probe"

	authenticatedcaching "github.com/cerberauth/proxyaudit/proxy/checks/caching/authenticated_caching"
	cachedeception "github.com/cerberauth/proxyaudit/proxy/checks/caching/cache_deception"
	cachepoisoning "github.com/cerberauth/proxyaudit/proxy/checks/caching/cache_poisoning"
	varyconsistency "github.com/cerberauth/proxyaudit/proxy/checks/caching/vary_consistency"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// ContextID is the internal check building the cache-detective context.
const ContextID harnessx.CheckID = "proxy.caching.context"

// Synthetic credentials sent so the authenticated-cacheable detection has an
// Authorization header and a cookie to test against.
const (
	authProbeBearer     = "proxyaudit-cache-probe-token"
	authProbeCookieName = "session"
	authProbeCookie     = "proxyaudit-cache-probe"
)

// Defs maps the cache-detective checks proxyaudit reports to its own
// definitions.
var Defs = map[harnessx.CheckID]checkdef.CheckDef{
	cdcheckbase.CheckIDAuthCacheable:  authenticatedcaching.Def,
	cdcheckbase.CheckIDVaryKey:        varyconsistency.Def,
	cdcheckbase.CheckIDUnkeyedHeader:  cachepoisoning.Def,
	cdcheckbase.CheckIDCacheDeception: cachedeception.Def,
}

// supporting are the pack checks the reported ones read results from; they
// run but stay internal. Any other pack check is skipped.
var supporting = map[harnessx.CheckID]bool{
	cdcheckbase.CheckIDCacheability: true,
}

// NewProbeCtx builds the cache-detective context from proxyaudit's
// ScanContext.
func NewProbeCtx(sctx *scanctx.ScanContext) *cdcheckbase.ProbeCtx {
	var transport http.RoundTripper
	var timeout time.Duration
	if sctx.HTTPClient != nil {
		transport = sctx.HTTPClient.Transport
		timeout = sctx.HTTPClient.Timeout
	}
	return cache.NewProbeCtx(cdcheckbase.ProbeCtx{
		Probe:       probe.New(probe.WithTransport(transport), probe.WithTimeout(timeout)),
		BearerToken: authProbeBearer,
		Cookies:     []cdcheckbase.Cookie{{Name: authProbeCookieName, Value: authProbeCookie}},
		Aggressive:  sctx.Aggressive,
	})
}

// Checks returns the caching checks, ready to register next to
// probebase.HTTPFetchCheck.
func Checks() []harnessx.Check {
	ids := make([]harnessx.CheckID, 0, len(Defs))
	for id := range Defs {
		ids = append(ids, id)
	}
	pack, err := embed.Select(cache.Checks(), ids...)
	if err != nil {
		panic(err)
	}

	hostID := func(id harnessx.CheckID) harnessx.CheckID {
		if def, ok := Defs[id]; ok {
			return harnessx.CheckID(def.ID)
		}
		return "proxy." + id
	}
	checks := embed.MustChecks(pack, embed.Options{
		Scope:     harnessx.ScopeGlobal,
		Rename:    hostID,
		ContextID: ContextID,
		DependsOn: []harnessx.CheckID{probebase.HTTPFetchCheckID},
		Skip:      probebase.SkipUnlessFetched,
		Context: func(_ context.Context, target harnessx.Target, _ *harnessx.Resource) (any, error) {
			return NewProbeCtx(scanctx.TargetContext(target)), nil
		},
	})

	for _, pc := range pack {
		def, reported := Defs[pc.ID]
		for i := range checks {
			if checks[i].ID != hostID(pc.ID) {
				continue
			}
			switch {
			case reported:
				applyDef(&checks[i], def)
			case supporting[pc.ID]:
				checks[i].Internal = true
			default:
				checks[i].Internal = true
				checks[i].Skip = harnessx.SkipAlways("not run by proxyaudit")
			}
		}
	}
	return checks
}

func applyDef(c *harnessx.Check, def checkdef.CheckDef) {
	c.Name = def.Name
	c.Description = def.Description
	c.Link = def.Link
	c.Tags = def.Tags
	c.CVSSVector = def.CVSSVector
	c.CVSSScore = def.CVSSScore
	c.CWEID = def.CWEID
	c.CAPECID = def.CAPECID
	c.OWASP = def.OWASP
}
