// Package adapt turns a cache-detective ScopePerResource check — written
// to scan a list of discovered resources, reading its
// *checkbase.ProbeCtx from target.Data — into a plain proxyaudit
// ScopeGlobal check run against the single URL proxyaudit scans, without
// reimplementing any check's own probing/detection logic: Run calls the
// cache-detective check's RunResource function directly.
//
// This mirrors how vulnapi adapts jwtop's checks (see vulnapi's
// scan/broken_authentication/jwt/checkbase package) into its own engine.
package adapt

import (
	"context"
	"net/http"
	"time"

	cdcheckbase "github.com/cerberauth/cache-detective/cache/checkbase"
	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/probe"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// resourceID is the fixed ID of the single harnessx.Resource proxyaudit
// hands to a cache-detective check — proxyaudit scans exactly one URL per
// run, unlike cache-detective's own crawl/list/sitemap resource discovery.
const resourceID = "target"

// authProbeBearer and authProbeCookie are synthetic credentials sent with
// every probe request, so cache-detective's authenticated-cacheable
// detection (cache/checks/cacheability.AuthCheck) has an Authorization/
// Cookie to test against — proxyaudit has no real credentials for the
// target.
const (
	authProbeBearer     = "proxyaudit-cache-probe-token"
	authProbeCookieName = "session"
	authProbeCookie     = "proxyaudit-cache-probe"
)

// ProbeCtx builds the *cdcheckbase.ProbeCtx every cache-detective check run
// via Run expects on its inner Target.Data, from proxyaudit's ScanContext.
func ProbeCtx(sctx *scanctx.ScanContext) *cdcheckbase.ProbeCtx {
	var transport http.RoundTripper
	var timeout time.Duration
	if sctx.HTTPClient != nil {
		transport = sctx.HTTPClient.Transport
		timeout = sctx.HTTPClient.Timeout
	}
	pctx := cdcheckbase.ProbeCtx{
		Probe:       probe.New(probe.WithTransport(transport), probe.WithTimeout(timeout)),
		BearerToken: authProbeBearer,
		Cookies:     []cdcheckbase.Cookie{{Name: authProbeCookieName, Value: authProbeCookie}},
		Aggressive:  sctx.Aggressive,
	}.WithDefaults()
	return &pctx
}

// resource is the single harnessx.Resource a cache-detective check's
// RunResource runs against.
func resource(target harnessx.Target) harnessx.Resource {
	return harnessx.Resource{ID: resourceID, URL: target.URL, Method: http.MethodGet}
}

// innerTarget builds the single-target harnessx.Target cache-detective's
// checks expect: the same URL, with pctx as Data in place of proxyaudit's
// own *scanctx.ScanContext.
func innerTarget(target harnessx.Target, pctx *cdcheckbase.ProbeCtx) harnessx.Target {
	return harnessx.Target{URL: target.URL, Data: pctx}
}

// store is a minimal harnessx.ResultStore for gluing together a short,
// hand-run chain of cache-detective checks against the single resource
// proxyaudit scans — e.g. cacheability.AuthCheck reading
// cacheability.Check's stored analysis via GetForResource. It only ever
// holds the entries a Run caller explicitly seeds via deps.
type store struct {
	results map[harnessx.CheckID]harnessx.Result
}

func (s *store) Get(id harnessx.CheckID) (harnessx.Result, bool) {
	r, ok := s.results[id]
	return r, ok
}

func (s *store) GetForResource(id harnessx.CheckID, _ string) (harnessx.Result, bool) {
	return s.Get(id)
}

func (s *store) Observations() []harnessx.Observation { return nil }
func (s *store) Resources() []harnessx.Resource       { return nil }

// Run adapts a ScopePerResource cache-detective check (jc) into a call
// against the single resource proxyaudit scans: builds the ProbeCtx/
// Resource/Target shape jc expects, evaluates jc.Skip, and — unless
// skipped — calls jc.RunResource directly, completely unmodified. deps
// seeds the store with prior cache-detective Results (e.g.
// cacheability.Check's own Result) that jc's RunResource reads via
// store.GetForResource, for the few checks with a genuine data dependency
// on another cache-detective check.
func Run(ctx context.Context, target harnessx.Target, jc harnessx.Check, deps map[harnessx.CheckID]harnessx.Result) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)
	pctx := ProbeCtx(sctx)
	inner := innerTarget(target, pctx)
	res := resource(target)

	s := &store{results: deps}
	if s.results == nil {
		s.results = map[harnessx.CheckID]harnessx.Result{}
	}

	if reason := jc.Skip.EvalResource(ctx, inner, res, s); reason != "" {
		return harnessx.Result{Skipped: true, SkipReason: reason}, nil
	}
	return jc.RunResource(ctx, inner, res, s)
}
