// Package vhostconfusion sends a fixed list of common internal/admin Host
// header values and compares each response with a baseline request made
// with the target's own host, testing whether a crafted Host header
// routes the request to a different (potentially internal) backend —
// virtual-host confusion caused by trusting the client-supplied Host
// header for routing decisions.
package vhostconfusion

import (
	"bytes"
	"context"
	_ "embed"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("vhost_confusion", checkYAML)

// candidateHosts are hostname conventions an internal/admin virtual host
// is plausibly registered under on a proxy or origin that routes on the
// client-supplied Host header instead of the connection it was received
// on.
var candidateHosts = []string{
	"internal-admin.local", "admin.internal", "internal", "localhost", "127.0.0.1",
}

const maxEvidenceLen = 120

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	baseline, err := probebase.FetchWithHost(ctx, sctx, target.URL, "")
	if err != nil {
		return harnessx.Result{Err: err}, nil
	}
	if baseline.Err != nil {
		return harnessx.Result{Err: baseline.Err}, nil
	}

	var observations []harnessx.Observation
	for _, host := range candidateHosts {
		spoofed, err := probebase.FetchWithHost(ctx, sctx, target.URL, host)
		if err != nil {
			return harnessx.Result{Observations: observations, Err: err}, nil
		}
		if spoofed.Err != nil || bytes.Equal(spoofed.Body, baseline.Body) {
			continue
		}

		observations = append(observations, harnessx.Observation{
			Title:       "Virtual-host confusion via crafted Host header: " + host,
			Description: "Sending Host: " + host + " returned a different response body than the request's own host, indicating the proxy or origin routes to a different backend based on the client-supplied Host header — an attacker able to reach this listener could use it to route to an unintended (e.g. internal/admin) backend.",
			Evidence:    "GET with own Host -> " + truncate(baseline.Body) + "; GET with Host: " + host + " -> " + truncate(spoofed.Body),
			Metadata:    map[string]string{"host": host},
		})
	}

	return harnessx.Result{Observations: observations}, nil
})

func truncate(body []byte) string {
	s := string(body)
	if len(s) > maxEvidenceLen {
		return s[:maxEvidenceLen] + "..."
	}
	return s
}
