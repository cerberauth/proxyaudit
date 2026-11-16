// Package robot checks whether the target's RSA key exchange answers
// well-formed and malformed PKCS#1 v1.5 padding differently (ROBOT).
package robot

import (
	"context"
	_ "embed"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("robot", checkYAML)

const CodeROBOT = "cve.robot"

var probeROBOT = probebase.ProbeROBOT

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	host, err := probebase.TargetHost(target.URL)
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	result, err := probeROBOT(ctx, host)
	if err != nil || !result.Vulnerable {
		return harnessx.Result{}, nil
	}
	responses := strings.Join(result.Responses, ", ")
	return harnessx.Result{Observations: []harnessx.Observation{{
		Title:       "RSA padding oracle (ROBOT)",
		Description: "The target answered RSA key-exchange handshakes differently depending on the PKCS#1 v1.5 padding of the encrypted premaster secret, consistently across two rounds. An attacker can use this Bleichenbacher oracle to decrypt captured RSA key-exchange sessions or sign with the server's key.",
		Evidence:    "responses to correct padding, wrong prefix, misplaced zero, missing zero, wrong version: " + responses,
		Metadata:    map[string]string{probebase.MetadataCode: CodeROBOT, "cve": "CVE-2017-13099", "responses": responses},
	}}}, nil
}, checkdef.WithSkip(probebase.SkipUnlessHandshake()))
