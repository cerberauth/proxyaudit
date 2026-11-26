// Package heartbleed checks whether the target answers a TLS heartbeat
// request declaring a longer payload than it carries (CVE-2014-0160).
package heartbleed

import (
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("heartbleed", checkYAML)

const CodeHeartbleed = "cve.heartbleed"

var probeHeartbleed = probebase.ProbeHeartbleed

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	host, err := probebase.TargetHost(target.URL)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	if vulnerable, err := probeHeartbleed(ctx, host); err != nil || !vulnerable {
		return harnessx.Result{}, nil
	}
	return harnessx.Result{Observations: []harnessx.Observation{{
		Title:       "Heartbleed (CVE-2014-0160)",
		Description: "The target answered a TLS heartbeat request whose declared payload length exceeds the data sent, returning bytes read past the request from its process memory. An attacker can repeat it to read private keys, session cookies and credentials.",
		Evidence:    "heartbeat request declaring a 16-byte payload with none sent was answered with a heartbeat response (leaked bytes discarded)",
		Metadata:    map[string]string{probebase.MetadataCode: CodeHeartbleed, "cve": "CVE-2014-0160"},
	}}}, nil
}, checkdef.WithSkip(probebase.SkipUnlessHandshake()))
