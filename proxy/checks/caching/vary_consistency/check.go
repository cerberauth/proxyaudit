// Package varyconsistency holds the definition of the proxy.caching.vary_consistency check,
// which runs cache-detective's cache.vary_key check (see the caching package).
package varyconsistency

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("vary_consistency", checkYAML)
