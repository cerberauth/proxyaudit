package robot

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/proxyaudit/proxy/probebase"
)

const decryptError = "alert 2 51"

func TestCheck_PaddingOracle(t *testing.T) {
	t.Cleanup(func(previous func(context.Context, string) (*probebase.RobotResult, error)) func() {
		return func() { probeROBOT = previous }
	}(probeROBOT))
	probeROBOT = func(context.Context, string) (*probebase.RobotResult, error) {
		return &probebase.RobotResult{Vulnerable: true, Responses: []string{"alert 2 20", decryptError, decryptError, decryptError, "alert 2 20"}}, nil
	}

	result, err := Check.Run(context.Background(), harnessx.Target{URL: "https://127.0.0.1:1"}, harnessx.NewStaticResultStore())

	require.NoError(t, err)
	require.Len(t, result.Observations, 1)
	assert.Equal(t, CodeROBOT, result.Observations[0].Metadata["code"])
	assert.Contains(t, result.Observations[0].Evidence, decryptError)
}
