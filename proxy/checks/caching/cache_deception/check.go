// Package cachedeception holds the definition of the proxy.caching.cache_deception check,
// which runs cache-detective's cache.cache_deception check (see the caching package).
package cachedeception

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("cache_deception", checkYAML)
