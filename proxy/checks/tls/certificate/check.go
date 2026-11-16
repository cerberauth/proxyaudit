// Package certificate checks the leaf certificate presented during the
// shared TLS handshake for chain trust, expiry window, hostname match, and
// OCSP stapling.
package certificate

import (
	"bytes"
	"context"
	"crypto/x509"
	_ "embed"
	"errors"
	"net/url"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

var errNoCertificate = errors.New("no certificate available from probe.tls_info")

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("certificate", checkYAML)

// ExpiryWarningWindow flags a certificate that is still valid but expires
// soon enough to be an operational risk.
const ExpiryWarningWindow = 30 * 24 * time.Hour

const (
	CodeUntrustedChain   = "certificate.untrusted_chain"
	CodeSelfSigned       = "certificate.self_signed"
	CodeHostnameMismatch = "certificate.hostname_mismatch"
	CodeExpired          = "certificate.expired"
	CodeNotYetValid      = "certificate.not_yet_valid"
	CodeExpiresSoon      = "certificate.expires_soon"
	CodeOCSPNotStapled   = "certificate.ocsp_not_stapled"
)

func isSelfSigned(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawIssuer, cert.RawSubject) && cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}

func chainError(leaf *x509.Certificate, intermediates []*x509.Certificate, roots *x509.CertPool) error {
	pool := x509.NewCertPool()
	for _, c := range intermediates {
		pool.AddCert(c)
	}
	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: pool,
		CurrentTime:   leaf.NotBefore.Add(time.Second),
	})
	return err
}

func observation(code, title, description, evidence string, metadata map[string]string) harnessx.Observation {
	if metadata == nil {
		metadata = map[string]string{}
	}
	metadata[probebase.MetadataCode] = code
	return harnessx.Observation{Title: title, Description: description, Evidence: evidence, Metadata: metadata}
}

var Check = checkdef.NewCheck(Def, func(_ context.Context, target harnessx.Target, store harnessx.ResultStore) (harnessx.Result, error) {
	info, ok := probebase.Info(store)
	if !ok || info.Err != nil || info.ConnState == nil || len(info.ConnState.PeerCertificates) == 0 {
		return harnessx.Result{Err: errNoCertificate}, nil
	}
	sctx := scanctx.TargetContext(target)
	leaf := info.ConnState.PeerCertificates[0]
	subject := map[string]string{"subject": leaf.Subject.String()}

	var observations []harnessx.Observation

	if err := chainError(leaf, info.ConnState.PeerCertificates[1:], sctx.RootCAs); err != nil {
		var unknownAuthority x509.UnknownAuthorityError
		if errors.As(err, &unknownAuthority) && isSelfSigned(leaf) {
			observations = append(observations, observation(CodeSelfSigned,
				"Certificate is self-signed",
				"The certificate presented by the target is signed by its own key instead of a trusted certificate authority, so clients cannot authenticate the server.",
				err.Error(), subject))
		} else {
			observations = append(observations, observation(CodeUntrustedChain,
				"Certificate chain does not verify",
				"The certificate presented by the target does not chain to a trusted root.",
				err.Error(), subject))
		}
	}

	if u, err := url.Parse(target.URL); err == nil {
		if err := leaf.VerifyHostname(u.Hostname()); err != nil {
			observations = append(observations, observation(CodeHostnameMismatch,
				"Certificate hostname does not match",
				"The certificate presented by the target is not valid for the hostname of the target URL.",
				err.Error(), map[string]string{"subject": leaf.Subject.String(), "hostname": u.Hostname()}))
		}
	}

	now := time.Now()
	notAfter := map[string]string{"not_after": leaf.NotAfter.Format(time.RFC3339)}
	switch {
	case now.After(leaf.NotAfter):
		observations = append(observations, observation(CodeExpired,
			"Certificate has expired",
			"The certificate presented by the target expired and is no longer valid.",
			"not_after: "+leaf.NotAfter.Format(time.RFC3339), notAfter))
	case now.Before(leaf.NotBefore):
		observations = append(observations, observation(CodeNotYetValid,
			"Certificate is not valid yet",
			"The certificate presented by the target is not valid before a future date.",
			"not_before: "+leaf.NotBefore.Format(time.RFC3339), map[string]string{"not_before": leaf.NotBefore.Format(time.RFC3339)}))
	case leaf.NotAfter.Before(now.Add(ExpiryWarningWindow)):
		observations = append(observations, observation(CodeExpiresSoon,
			"Certificate expires soon",
			"The certificate presented by the target expires within 30 days.",
			"not_after: "+leaf.NotAfter.Format(time.RFC3339), notAfter))
	}

	if info.ConnState.OCSPResponse == nil {
		observations = append(observations, observation(CodeOCSPNotStapled,
			"OCSP stapling not enabled",
			"The target did not staple an OCSP response during the TLS handshake, so clients must query the CA's OCSP responder separately (or skip revocation checking entirely).",
			"no OCSP response in TLS handshake", nil))
	}

	return harnessx.Result{Observations: observations}, nil
}, checkdef.WithSkip(harnessx.SkipWhen(func(_ context.Context, _ harnessx.Target, store harnessx.ResultStore) string {
	info, _ := probebase.Info(store)
	if reason := info.SkipReason(); reason != "" {
		return reason
	}
	if len(info.ConnState.PeerCertificates) == 0 {
		return "target TLS handshake produced no certificate"
	}
	return ""
})))
