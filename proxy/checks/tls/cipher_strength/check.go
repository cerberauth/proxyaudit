// Package cipherstrength checks the negotiated TLS cipher suite for
// forward secrecy and probes whether the target still accepts any
// known-weak cipher suite (RC4, 3DES, CBC-mode) that Go's crypto/tls
// implements but excludes from its default client offer.
package cipherstrength

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

var Def = checkdef.MustParseCheckDefYAML("cipher_strength", checkYAML)

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	var observations []harnessx.Observation

	if info, ok := probebase.Info(store); ok && info.Err == nil && info.ConnState != nil {
		name := tls.CipherSuiteName(info.ConnState.CipherSuite)
		if !hasForwardSecrecy(name, info.ConnState.Version) {
			observations = append(observations, harnessx.Observation{
				Title:       "Negotiated cipher suite lacks forward secrecy",
				Description: "The default TLS handshake negotiated a cipher suite that does not provide forward secrecy, so a compromised private key could decrypt captured past traffic.",
				Evidence:    "negotiated cipher suite: " + name,
				Metadata:    map[string]string{"cipher_suite": name},
			})
		}
	}

	host, err := probebase.TargetHost(target.URL)
	if err != nil {
		return harnessx.Result{Observations: observations, Err: err}, nil
	}

	weak := insecureSuiteIDs()
	if len(weak) > 0 {
		state, err := probebase.DialTLS(ctx, host, sctx, tls.VersionTLS10, tls.VersionTLS12, weak...)
		if err == nil && state != nil {
			observations = append(observations, harnessx.Observation{
				Title:       "Weak cipher suite accepted",
				Description: "The target completed a TLS handshake using a known-weak cipher suite (RC4, 3DES, or a CBC-mode suite).",
				Evidence:    "negotiated cipher suite: " + tls.CipherSuiteName(state.CipherSuite),
				Metadata:    map[string]string{"cipher_suite": tls.CipherSuiteName(state.CipherSuite)},
			})
		}
	}

	return harnessx.Result{Observations: observations}, nil
}, checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, target harnessx.Target, store harnessx.ResultStore) string {
	info, ok := probebase.Info(store)
	if !ok || info.Err != nil {
		return "target TLS handshake failed — see probe.tls_info"
	}
	return ""
})))

// hasForwardSecrecy reports whether the negotiated cipher suite provides
// forward secrecy. TLS 1.3 suites are always forward-secret (fixed ECDHE
// key exchange); for TLS 1.2 and below, only ECDHE/DHE key-exchange suites
// qualify.
func hasForwardSecrecy(cipherSuiteName string, version uint16) bool {
	if version == tls.VersionTLS13 {
		return true
	}
	return strings.Contains(cipherSuiteName, "ECDHE") || strings.Contains(cipherSuiteName, "DHE")
}

// insecureSuiteIDs returns the IDs of cipher suites Go's crypto/tls
// implements but marks insecure (RC4, 3DES, CBC-mode, ...) — excluded from
// the client's default offer, so they must be requested explicitly to test
// whether the server still accepts them.
func insecureSuiteIDs() []uint16 {
	suites := tls.InsecureCipherSuites()
	ids := make([]uint16, len(suites))
	for i, s := range suites {
		ids[i] = s.ID
	}
	return ids
}
