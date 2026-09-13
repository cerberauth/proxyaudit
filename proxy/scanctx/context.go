// Package scanctx defines proxy's scenario context — ScanContext — kept
// as a separate leaf package (rather than living in the proxy root) so
// both individual checks and proxy's own check registry (which imports
// every check package) can depend on it without an import cycle.
package scanctx

import (
	"crypto/x509"
	"net/http"

	"github.com/cerberauth/harnessx"
)

// ProxyEngine identifies (or hints at) the reverse proxy / gateway software
// fronting the target, so checks can adjust applicability or evidence
// paths (e.g. Traefik's /api/, Envoy's admin interface).
type ProxyEngine string

const (
	EngineUnknown ProxyEngine = "unknown"
	EngineNginx   ProxyEngine = "nginx"
	EngineTraefik ProxyEngine = "traefik"
	EngineEnvoy   ProxyEngine = "envoy"
	EngineCaddy   ProxyEngine = "caddy"
	EngineHAProxy ProxyEngine = "haproxy"
)

// ScanContext carries scenario axes so the same check can adjust
// applicability/severity based on context. It is stored as
// harnessx.Target.Data and read back by checks via TargetContext, mirroring
// how jwtop's checkbase.ProbeCtx rides along on harnessx.Target.Data.
//
// Extend this struct in later milestones (e.g. DeploymentModel,
// TLSTerminationPoint) rather than creating parallel context types.
type ScanContext struct {
	// Engine hints the fronting proxy software, either detected or
	// supplied via --engine. EngineUnknown is a valid, common value.
	Engine ProxyEngine

	// Aggressive gates Agg-tier checks not yet present in v0.1 — checks
	// that are more intrusive or more likely to produce noise/false
	// positives. Must default false.
	Aggressive bool

	// HTTPClient is the client checks use for ordinary requests. Defaults
	// to http.DefaultClient via TargetContext when nil.
	HTTPClient *http.Client

	// RootCAs overrides the trust store used to verify the target's TLS
	// certificate chain. Nil means the system trust store. Tests set this
	// to a pool containing the test server's self-signed certificate.
	RootCAs *x509.CertPool
}

// NewTarget builds a harnessx.Target for url carrying sctx as Target.Data,
// the shape every proxy check expects.
func NewTarget(url string, sctx *ScanContext) harnessx.Target {
	if sctx == nil {
		sctx = &ScanContext{}
	}
	return harnessx.Target{URL: url, Data: sctx}
}

// TargetContext reads the *ScanContext off target.Data, falling back to a
// zero-value context (HTTPClient defaulted) if the target wasn't built via
// NewTarget.
func TargetContext(target harnessx.Target) *ScanContext {
	sctx, ok := target.Data.(*ScanContext)
	if !ok || sctx == nil {
		sctx = &ScanContext{}
	}
	if sctx.HTTPClient == nil {
		sctx.HTTPClient = http.DefaultClient
	}
	return sctx
}
