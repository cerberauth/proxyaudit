// Package drown checks whether the target still accepts SSLv2, which
// exposes every TLS session sharing its RSA key to DROWN (CVE-2016-0800).
package drown

import (
	"context"
	_ "embed"
	"strconv"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("drown", checkYAML)

const CodeDROWN = "cve.drown"

var probeSSLv2 = probebase.ProbeSSLv2

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	host, err := probebase.TargetHost(target.URL)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	hello, err := probeSSLv2(ctx, host)
	if err != nil {
		return harnessx.Result{}, nil
	}
	ciphers := strconv.Itoa(hello.CipherSpecs)
	return harnessx.Result{Observations: []harnessx.Observation{{
		Title:       "SSLv2 enabled (DROWN, CVE-2016-0800)",
		Description: "The target answered an SSLv2 ClientHello with an SSLv2 ServerHello. An attacker can use SSLv2 as a Bleichenbacher oracle to decrypt captured TLS sessions protected by the same RSA key, even on other servers sharing that key.",
		Evidence:    "SSLv2 ServerHello offering " + ciphers + " cipher specs",
		Metadata:    map[string]string{probebase.MetadataCode: CodeDROWN, "cve": "CVE-2016-0800", "cipher_specs": ciphers},
	}}}, nil
}, checkdef.WithSkip(probebase.SkipUnlessHandshake()))
