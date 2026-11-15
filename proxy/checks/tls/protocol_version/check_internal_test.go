package protocolversion

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

func TestCheck_SSL30Accepted(t *testing.T) {
	t.Cleanup(func() { probeLegacyHello = probebase.ProbeLegacyHello })
	probeLegacyHello = func(context.Context, string, uint16, []uint16) (*probebase.LegacyHello, error) {
		return &probebase.LegacyHello{Version: probebase.VersionSSL30, CipherSuite: 0x000a}, nil
	}

	result, err := Check.Run(context.Background(), harnessx.Target{URL: "https://127.0.0.1:1"}, harnessx.NewStaticResultStore())

	require.NoError(t, err)
	require.Len(t, result.Observations, 1)
	assert.Equal(t, CodeLegacyEnabled, result.Observations[0].Metadata["code"])
	assert.Equal(t, "SSL 3.0", result.Observations[0].Metadata["versions"])
}
