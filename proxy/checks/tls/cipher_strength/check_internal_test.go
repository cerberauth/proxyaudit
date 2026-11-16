package cipherstrength

import (
	"context"
	"crypto/tls"
	"errors"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"

	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

func TestCheck_LegacySuitesAndWeakDH(t *testing.T) {
	t.Cleanup(func() { probeLegacyHello = probebase.ProbeLegacyHello })
	probeLegacyHello = func(_ context.Context, _ string, _ uint16, suites []uint16) (*probebase.LegacyHello, error) {
		switch suites[0] {
		case probebase.NULLSuites[0]:
			return &probebase.LegacyHello{Version: probebase.VersionTLS12, CipherSuite: 0x0002}, nil
		case probebase.DHESuites[0]:
			return &probebase.LegacyHello{Version: probebase.VersionTLS12, CipherSuite: 0x0033, DHPrimeBits: 1024}, nil
		case probebase.RC4Suites[0]:
			return &probebase.LegacyHello{Version: probebase.VersionTLS12, CipherSuite: 0x002f}, nil
		}
		return nil, errors.New("rejected")
	}
	store := harnessx.NewStaticResultStore(harnessx.ResultData(probebase.TLSInfoCheckID, &probebase.TLSInfo{
		ConnState: &tls.ConnectionState{Version: tls.VersionTLS13, CipherSuite: tls.TLS_AES_128_GCM_SHA256},
	}))

	result, err := Check.Run(context.Background(), harnessx.Target{URL: "https://127.0.0.1:1"}, store)

	assert.NoError(t, err)
	var codes []string
	for _, o := range result.Observations {
		codes = append(codes, o.Metadata["code"])
	}
	assert.ElementsMatch(t, []string{CodeNULL, CodeWeakDH}, codes)
}
