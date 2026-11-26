// Package cachepoisoning holds the definition of the proxy.caching.cache_poisoning check,
// which runs cache-detective's cache.unkeyed_header_injection check (see the caching package).
package cachepoisoning

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("cache_poisoning", checkYAML)
