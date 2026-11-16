// Package authenticatedcaching holds the definition of the proxy.caching.authenticated_caching check,
// which runs cache-detective's cache.authenticated_cacheable check (see the caching package).
package authenticatedcaching

import (
	_ "embed"

	"github.com/cerberauth/harnessx/checkdef"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("authenticated_caching", checkYAML)
