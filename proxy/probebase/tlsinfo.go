package probebase

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/url"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// TLSInfoCheckID is the shared check the checks/tls checks depend on for
// the negotiated TLS connection state (default handshake, no forced
// version).
const TLSInfoCheckID harnessx.CheckID = "probe.tls_info"

// DialTimeout bounds every TLS handshake proxy performs.
const DialTimeout = 10 * time.Second

// TLSInfo is the shared TLS handshake outcome every checks/tls check
// inspects.
type TLSInfo struct {
	ConnState *tls.ConnectionState
	// VerifyErr is the result of independently verifying the presented
	// chain against sctx.RootCAs (or the system trust store) and hostname
	// — kept separate from Err because the handshake itself always
	// completes (see DialTLS's InsecureSkipVerify), so a bad chain is a
	// finding for checks/tls/certificate, not a probe failure.
	VerifyErr error
	Err       error
}

// TargetHost extracts host:port (port defaulting to 443) from a target URL.
func TargetHost(rawURL string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	hostname := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(hostname, port), nil
}

// DialTLS performs a TLS handshake against host ("host:port") constrained
// to [minVersion, maxVersion] (both zero means the Go default range) and,
// if non-empty, to cipherSuites, and returns the negotiated connection
// state. The handshake always skips certificate verification — proxy
// checks certificate trust independently via VerifyCertificate, so a bad
// chain doesn't prevent probing protocol version or cipher suite support.
// The connection is closed before returning — proxy only needs handshake
// metadata, not a live conn.
func DialTLS(ctx context.Context, host string, sctx *scanctx.ScanContext, minVersion, maxVersion uint16, cipherSuites ...uint16) (*tls.ConnectionState, error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}

	dialer := &net.Dialer{Timeout: DialTimeout}
	tlsDialer := &tls.Dialer{
		NetDialer: dialer,
		Config: &tls.Config{
			ServerName:         hostname,
			MinVersion:         minVersion,
			MaxVersion:         maxVersion,
			CipherSuites:       cipherSuites,
			InsecureSkipVerify: true, //nolint:gosec // verified separately via VerifyCertificate
		},
	}

	conn, err := tlsDialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	state := conn.(*tls.Conn).ConnectionState()
	return &state, nil
}

// VerifyCertificate independently verifies state's peer certificate chain
// against sctx.RootCAs (nil meaning the system trust store) and hostname,
// mirroring the validation crypto/tls would have performed had DialTLS not
// skipped it.
func VerifyCertificate(state *tls.ConnectionState, sctx *scanctx.ScanContext, hostname string) error {
	if state == nil || len(state.PeerCertificates) == 0 {
		return nil
	}
	leaf := state.PeerCertificates[0]

	intermediates := x509.NewCertPool()
	for _, c := range state.PeerCertificates[1:] {
		intermediates.AddCert(c)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		DNSName:       hostname,
		Roots:         sctx.RootCAs,
		Intermediates: intermediates,
	})
	return err
}

// TLSInfoCheck performs the single shared TLS handshake against the target
// host, using the Go default version/cipher negotiation, plus an
// independent certificate chain/hostname verification. It does not itself
// report a finding.
var TLSInfoCheck = checkdef.NewCheck(
	checkdef.CheckDef{ID: string(TLSInfoCheckID), Name: "TLS Info"},
	func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
		sctx := scanctx.TargetContext(target)

		host, err := TargetHost(target.URL)
		if err != nil {
			return harnessx.DataResult(&TLSInfo{Err: err}), nil
		}

		state, err := DialTLS(ctx, host, sctx, 0, 0)
		if err != nil {
			return harnessx.DataResult(&TLSInfo{Err: err}), nil
		}

		hostname, _, splitErr := net.SplitHostPort(host)
		if splitErr != nil {
			hostname = host
		}
		verifyErr := VerifyCertificate(state, sctx, hostname)

		return harnessx.DataResult(&TLSInfo{ConnState: state, VerifyErr: verifyErr}), nil
	},
)

// Info reads the shared TLSInfo off store, populated by TLSInfoCheck.
func Info(store harnessx.ResultStore) (*TLSInfo, bool) {
	return harnessx.GetData[*TLSInfo](store, TLSInfoCheckID)
}
