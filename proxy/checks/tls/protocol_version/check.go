// Package protocolversion checks whether the target still accepts
// deprecated TLS protocol versions (TLS 1.0/1.1) — Go's crypto/tls no
// longer implements SSLv3, so that version can't be probed directly, but
// a server still offering it would also offer TLS 1.0/1.1 in virtually
// every real deployment, which this check does detect.
package protocolversion

import (
	"context"
	"crypto/tls"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("protocol_version", checkYAML)

// deprecatedVersions are probed individually (via MaxVersion) since a
// server negotiating a modern default doesn't reveal what older versions
// it would still accept.
var deprecatedVersions = []struct {
	name    string
	version uint16
}{
	{"TLS 1.0", tls.VersionTLS10},
	{"TLS 1.1", tls.VersionTLS11},
}

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	host, err := probebase.TargetHost(target.URL)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}

	var observations []harnessx.Observation
	for _, v := range deprecatedVersions {
		state, err := probebase.DialTLS(ctx, host, sctx, v.version, v.version)
		if err != nil {
			// Handshake failure at this forced version means the server
			// rejected it — the desired, secure outcome.
			continue
		}
		observations = append(observations, harnessx.Observation{
			Title:       "Deprecated TLS version accepted: " + v.name,
			Description: "The target completed a TLS handshake using " + v.name + ", a deprecated protocol version with known weaknesses.",
			Evidence:    "negotiated version: " + tlsVersionName(state.Version),
			Metadata:    map[string]string{"tls_version": v.name},
		})
	}

	return harnessx.Result{Observations: observations}, nil
}, checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, store harnessx.ResultStore) string {
	info, ok := probebase.Info(store)
	if !ok || info.Err != nil {
		return "target TLS handshake failed — see probe.tls_info"
	}
	return ""
})))

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "unknown"
	}
}
