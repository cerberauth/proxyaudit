package proxy_test

import (
	"testing"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/cerberauth/proxyaudit/proxy"
)

func TestAllChecks_RegistersWithoutError(t *testing.T) {
	checks, defs := proxy.AllChecks()
	require.NotEmpty(t, checks)

	engine := harnessx.New(harnessx.WithChecks(checks...))
	assert.NotNil(t, engine)

	// Every check with descriptive metadata (everything but the two shared
	// probes) must have a matching CheckDef, so proxyaudit's reporting
	// layer has CVSS/CWE/OWASP for it.
	for _, c := range checks {
		if c.ID == "probe.http_fetch" || c.ID == "probe.tls_info" {
			continue
		}
		_, ok := defs[c.ID]
		assert.True(t, ok, "missing CheckDef for %s", c.ID)
	}
}
