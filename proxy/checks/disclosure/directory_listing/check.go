// Package directorylisting probes common static-asset paths for
// autoindex-style directory listings.
package directorylisting

import (
	"bytes"
	"context"
	_ "embed"
	"net/http"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/checkdef"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

//go:embed check.yaml
var checkYAML []byte

var Def = checkdef.MustParseCheckDefYAML("directory_listing", checkYAML)

func looksLikeListing(status int, _ http.Header, body []byte) bool {
	if status != http.StatusOK {
		return false
	}
	for _, marker := range [][]byte{
		[]byte("Index of /"),
		[]byte("<title>Directory listing for"),
		[]byte("Parent Directory</a>"),
	} {
		if bytes.Contains(body, marker) {
			return true
		}
	}
	return false
}

var paths = []string{"/", "/static/", "/assets/", "/files/", "/public/", "/uploads/"}

var signatures = func() []probebase.PathSignature {
	sigs := make([]probebase.PathSignature, len(paths))
	for i, p := range paths {
		sigs[i] = probebase.PathSignature{
			Path:        p,
			Title:       "Directory listing enabled at " + p,
			Description: "The target returned an autoindex-style directory listing for " + p + ", exposing the file/directory structure to anyone.",
			Match:       looksLikeListing,
		}
	}
	return sigs
}()

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	observations, err := probebase.ProbePaths(ctx, sctx, target.URL, signatures)
	if err != nil {
		return harnessx.Result{Observations: observations, Err: err}, nil
	}
	return harnessx.Result{Observations: observations}, nil
})
