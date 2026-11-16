package heartbleed

import (
	"context"
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheck_HeartbeatAnswered(t *testing.T) {
	t.Cleanup(func(previous func(context.Context, string) (bool, error)) func() {
		return func() { probeHeartbleed = previous }
	}(probeHeartbleed))
	probeHeartbleed = func(context.Context, string) (bool, error) { return true, nil }

	result, err := Check.Run(context.Background(), harnessx.Target{URL: "https://127.0.0.1:1"}, harnessx.NewStaticResultStore())

	require.NoError(t, err)
	require.Len(t, result.Observations, 1)
	assert.Equal(t, CodeHeartbleed, result.Observations[0].Metadata["code"])
	assert.Equal(t, "CVE-2014-0160", result.Observations[0].Metadata["cve"])
}
