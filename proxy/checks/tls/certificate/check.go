// Package certificate checks the leaf certificate presented during the
// shared TLS handshake for chain trust, expiry window, hostname match, and
// OCSP stapling.
package certificate

import (
	"context"
	_ "embed"
	"errors"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

var errNoCertificate = errors.New("no certificate available from probe.tls_info")

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("certificate", checkYAML)

// ExpiryWarningWindow flags a certificate that is still valid but expires
// soon enough to be an operational risk.
const ExpiryWarningWindow = 30 * 24 * time.Hour

var Check = checkdef.NewCheck(Def, func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	info, ok := probebase.Info(store)
	if !ok || info.Err != nil || info.ConnState == nil || len(info.ConnState.PeerCertificates) == 0 {
		return harnessx.Result{Err: errNoCertificate}, nil
	}
	leaf := info.ConnState.PeerCertificates[0]

	var observations []harnessx.Observation

	if info.VerifyErr != nil {
		observations = append(observations, harnessx.Observation{
			Title:       "Certificate chain does not verify",
			Description: "The certificate presented by the target does not chain to a trusted root, or the hostname does not match.",
			Evidence:    info.VerifyErr.Error(),
			Metadata:    map[string]string{"subject": leaf.Subject.String()},
		})
	}

	now := time.Now()
	switch {
	case now.After(leaf.NotAfter):
		observations = append(observations, harnessx.Observation{
			Title:       "Certificate has expired",
			Description: "The certificate presented by the target expired and is no longer valid.",
			Evidence:    "not_after: " + leaf.NotAfter.Format(time.RFC3339),
			Metadata:    map[string]string{"not_after": leaf.NotAfter.Format(time.RFC3339)},
		})
	case leaf.NotAfter.Before(now.Add(ExpiryWarningWindow)):
		observations = append(observations, harnessx.Observation{
			Title:       "Certificate expires soon",
			Description: "The certificate presented by the target expires within 30 days.",
			Evidence:    "not_after: " + leaf.NotAfter.Format(time.RFC3339),
			Metadata:    map[string]string{"not_after": leaf.NotAfter.Format(time.RFC3339)},
		})
	}

	if info.ConnState.OCSPResponse == nil {
		observations = append(observations, harnessx.Observation{
			Title:       "OCSP stapling not enabled",
			Description: "The target did not staple an OCSP response during the TLS handshake, so clients must query the CA's OCSP responder separately (or skip revocation checking entirely).",
			Evidence:    "no OCSP response in TLS handshake",
		})
	}

	return harnessx.Result{Observations: observations}, nil
}, checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) string {
	info, ok := probebase.Info(store)
	if !ok || info.Err != nil || info.ConnState == nil || len(info.ConnState.PeerCertificates) == 0 {
		return "target TLS handshake produced no certificate — see probe.tls_info"
	}
	return ""
})))
