// Package protocolversion checks whether the target still accepts
// deprecated protocol versions: SSL 3.0 through a raw ClientHello, and
// TLS 1.0/1.1 through crypto/tls.
package protocolversion

import (
	"context"
	"crypto/tls"
	_ "embed"
	"strings"

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

const CodeLegacyEnabled = "protocol.legacy_enabled"

var probeLegacyHello = probebase.ProbeLegacyHello

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	host, err := probebase.TargetHost(target.URL)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}

	var accepted []string
	if hello, err := probeLegacyHello(ctx, host, probebase.VersionSSL30, probebase.SSL3Suites); err == nil && hello.Version == probebase.VersionSSL30 {
		accepted = append(accepted, "SSL 3.0")
	}
	for _, v := range deprecatedVersions {
		if _, err := probebase.DialTLS(ctx, host, sctx, v.version, v.version, probebase.AllCipherSuites()...); err == nil {
			accepted = append(accepted, v.name)
		}
	}
	if len(accepted) == 0 {
		return harnessx.Result{}, nil
	}

	versions := strings.Join(accepted, ", ")
	return harnessx.Result{Observations: []harnessx.Observation{{
		Title:       "Deprecated protocol versions accepted: " + versions,
		Description: "The target completed a handshake using deprecated protocol versions with known weaknesses (POODLE, BEAST and the downgrade attacks they enable).",
		Evidence:    "accepted versions: " + versions,
		Metadata:    map[string]string{probebase.MetadataCode: CodeLegacyEnabled, "versions": versions},
	}}}, nil
}, checkdef.WithSkip(probebase.SkipUnlessHandshake()))
