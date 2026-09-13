package probebase

import (
	"context"
	"net/http"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// PathSignature is a single path to probe plus how to recognize a genuine
// exposure hit rather than an ordinary 404/403 (many proxies/apps return
// 200 for unknown paths, so status alone isn't reliable).
type PathSignature struct {
	Path        string
	Title       string
	Description string
	Match       func(status int, header http.Header, body []byte) bool
}

// ProbePaths runs ProbePath for every signature (a handful of requests,
// non-destructive) and returns one Observation per signature whose Match
// fires.
func ProbePaths(ctx context.Context, sctx *scanctx.ScanContext, baseURL string, sigs []PathSignature) ([]harnessx.Observation, error) {
	var observations []harnessx.Observation
	for _, sig := range sigs {
		result, err := ProbePath(ctx, sctx, baseURL, sig.Path)
		if err != nil {
			return observations, err
		}
		if result.Err != nil {
			continue
		}
		if !sig.Match(result.StatusCode, result.Header, result.Body) {
			continue
		}
		observations = append(observations, harnessx.Observation{
			Title:       sig.Title,
			Description: sig.Description,
			Evidence:    "GET " + sig.Path + " -> " + http.StatusText(result.StatusCode),
			Metadata:    map[string]string{"path": sig.Path},
		})
	}
	return observations, nil
}
