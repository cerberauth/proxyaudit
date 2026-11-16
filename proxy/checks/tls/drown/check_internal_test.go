package drown

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

func TestCheck_SSLv2Accepted(t *testing.T) {
	t.Cleanup(func(previous func(context.Context, string) (*probebase.SSLv2Hello, error)) func() {
		return func() { probeSSLv2 = previous }
	}(probeSSLv2))
	probeSSLv2 = func(context.Context, string) (*probebase.SSLv2Hello, error) {
		return &probebase.SSLv2Hello{CipherSpecs: 7}, nil
	}

	result, err := Check.Run(context.Background(), harnessx.Target{URL: "https://127.0.0.1:1"}, harnessx.NewStaticResultStore())

	require.NoError(t, err)
	require.Len(t, result.Observations, 1)
	assert.Equal(t, CodeDROWN, result.Observations[0].Metadata["code"])
	assert.Equal(t, "7", result.Observations[0].Metadata["cipher_specs"])
}
