// Package cipherstrength checks the negotiated TLS cipher suite for
// forward secrecy and probes whether the target still accepts RC4, 3DES,
// NULL or other insecure cipher suites, or a weak Diffie-Hellman group.
package cipherstrength

import (
	"context"
	"crypto/tls"
	_ "embed"
	"fmt"
	"strconv"
	"strings"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("cipher_strength", checkYAML)

const (
	CodeNoForwardSecrecy = "cipher.no_forward_secrecy"
	CodeRC4              = "cipher.rc4"
	CodeTripleDES        = "cipher.3des"
	CodeNULL             = "cipher.null"
	CodeWeakSuite        = "cipher.weak_suite"
	CodeWeakDH           = "cipher.weak_dh"
)

const MinDHPrimeBits = 2048

const metadataCipherSuite = "cipher_suite"

var probeLegacyHello = probebase.ProbeLegacyHello

var legacyFamilies = []struct {
	code   string
	name   string
	suites []uint16
}{
	{CodeRC4, "RC4", probebase.RC4Suites},
	{CodeTripleDES, "3DES", probebase.TDESSuites},
	{CodeNULL, "NULL (no encryption)", probebase.NULLSuites},
}

func offered(suites []uint16, suite uint16) bool {
	for _, s := range suites {
		if s == suite {
			return true
		}
	}
	return false
}

func suiteName(id uint16) string {
	return fmt.Sprintf("%s (0x%04x)", tls.CipherSuiteName(id), id)
}

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
				Metadata:    map[string]string{probebase.MetadataCode: CodeNoForwardSecrecy, metadataCipherSuite: name},
			})
		}
	}

	host, err := probebase.TargetHost(target.URL)
	if err != nil {
		return harnessx.Result{Observations: observations, Err: err}, nil
	}

	for _, family := range legacyFamilies {
		hello, err := probeLegacyHello(ctx, host, probebase.VersionTLS12, family.suites)
		if err != nil || !offered(family.suites, hello.CipherSuite) {
			continue
		}
		observations = append(observations, harnessx.Observation{
			Title:       "Weak cipher suite accepted: " + family.name,
			Description: "The target completed a TLS handshake using a " + family.name + " cipher suite, which does not protect the confidentiality of the traffic.",
			Evidence:    "negotiated cipher suite: " + suiteName(hello.CipherSuite),
			Metadata:    map[string]string{probebase.MetadataCode: family.code, metadataCipherSuite: suiteName(hello.CipherSuite)},
		})
	}

	if weak := otherInsecureSuiteIDs(); len(weak) > 0 {
		state, err := probebase.DialTLS(ctx, host, sctx, tls.VersionTLS10, tls.VersionTLS12, weak...)
		if err == nil && state != nil {
			observations = append(observations, harnessx.Observation{
				Title:       "Weak cipher suite accepted",
				Description: "The target completed a TLS handshake using a cipher suite Go marks as insecure (CBC mode with SHA-256).",
				Evidence:    "negotiated cipher suite: " + tls.CipherSuiteName(state.CipherSuite),
				Metadata:    map[string]string{probebase.MetadataCode: CodeWeakSuite, metadataCipherSuite: tls.CipherSuiteName(state.CipherSuite)},
			})
		}
	}

	if hello, err := probeLegacyHello(ctx, host, probebase.VersionTLS12, probebase.DHESuites); err == nil && probebase.IsDHESuite(hello.CipherSuite) && hello.DHPrimeBits > 0 && hello.DHPrimeBits < MinDHPrimeBits {
		bits := strconv.Itoa(hello.DHPrimeBits)
		observations = append(observations, harnessx.Observation{
			Title:       "Weak Diffie-Hellman group accepted",
			Description: "The target negotiated a DHE cipher suite with a Diffie-Hellman group below 2048 bits, which can be broken by a well-resourced attacker (Logjam).",
			Evidence:    "DH prime: " + bits + " bits, cipher suite: " + suiteName(hello.CipherSuite),
			Metadata:    map[string]string{probebase.MetadataCode: CodeWeakDH, "dh_bits": bits, metadataCipherSuite: suiteName(hello.CipherSuite)},
		})
	}

	return harnessx.Result{Observations: observations}, nil
}, checkdef.WithSkip(probebase.SkipUnlessHandshake()))

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

func otherInsecureSuiteIDs() []uint16 {
	var ids []uint16
	for _, s := range tls.InsecureCipherSuites() {
		if strings.Contains(s.Name, "RC4") || strings.Contains(s.Name, "3DES") {
			continue
		}
		ids = append(ids, s.ID)
	}
	return ids
}
