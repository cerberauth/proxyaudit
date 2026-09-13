// Package exposedmanagement probes a fixed list of known reverse-proxy/
// gateway management paths (Traefik dashboard/API, HAProxy stats, Envoy
// admin) to test whether they are reachable without authentication.
package exposedmanagement

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

var Def = checkdef.MustParseCheckDefYAML("exposed_management", checkYAML)

func contains(body []byte, markers ...string) bool {
	for _, m := range markers {
		if bytes.Contains(body, []byte(m)) {
			return true
		}
	}
	return false
}

var signatures = []probebase.PathSignature{
	{
		Path:        "/api/rawdata",
		Title:       "Traefik API reachable without authentication",
		Description: "The Traefik API (/api/rawdata) responded successfully without authentication, exposing routing configuration and backend addresses.",
		Match: func(status int, _ http.Header, body []byte) bool {
			return status == http.StatusOK && contains(body, "\"routers\"", "\"services\"")
		},
	},
	{
		Path:        "/dashboard/",
		Title:       "Traefik dashboard reachable without authentication",
		Description: "The Traefik dashboard (/dashboard/) responded successfully without authentication.",
		Match: func(status int, _ http.Header, body []byte) bool {
			return status == http.StatusOK && contains(body, "Traefik")
		},
	},
	{
		Path:        "/haproxy?stats",
		Title:       "HAProxy stats page reachable without authentication",
		Description: "The HAProxy statistics page responded successfully without authentication, exposing backend pool health and traffic details.",
		Match: func(status int, _ http.Header, body []byte) bool {
			return status == http.StatusOK && contains(body, "HAProxy Statistics", "haproxy")
		},
	},
	{
		Path:        "/clusters",
		Title:       "Envoy admin interface reachable without authentication",
		Description: "The Envoy admin interface (/clusters) responded successfully without authentication, exposing upstream cluster configuration.",
		Match: func(status int, _ http.Header, body []byte) bool {
			return status == http.StatusOK && (contains(body, "::observability_name::") || contains(body, "cx_active"))
		},
	},
	{
		Path:        "/config_dump",
		Title:       "Envoy admin config dump reachable without authentication",
		Description: "The Envoy admin config dump (/config_dump) responded successfully without authentication, exposing the full runtime configuration.",
		Match: func(status int, _ http.Header, body []byte) bool {
			return status == http.StatusOK && contains(body, "\"configs\"", "bootstrap")
		},
	},
	{
		Path:        "/server_info",
		Title:       "Envoy admin server_info reachable without authentication",
		Description: "The Envoy admin server_info endpoint responded successfully without authentication, exposing version and uptime information.",
		Match: func(status int, _ http.Header, body []byte) bool {
			return status == http.StatusOK && contains(body, "\"version\"", "envoy")
		},
	},
	{
		Path:        "/nginx_status",
		Title:       "nginx stub_status reachable without authentication",
		Description: "The nginx stub_status page responded successfully without authentication, exposing connection counts.",
		Match: func(status int, _ http.Header, body []byte) bool {
			return status == http.StatusOK && contains(body, "Active connections")
		},
	},
	{
		Path:        "/server-status",
		Title:       "Apache/httpd mod_status reachable without authentication",
		Description: "The Apache server-status page responded successfully without authentication, exposing worker/request details.",
		Match: func(status int, _ http.Header, body []byte) bool {
			return status == http.StatusOK && contains(body, "Server Status", "Apache Server Status")
		},
	},
}

var Check = checkdef.NewCheck(Def, func(ctx context.Context, target harnessx.Target, _ harnessx.ResultStore) (harnessx.Result, error) {
	sctx := scanctx.TargetContext(target)

	observations, err := probebase.ProbePaths(ctx, sctx, target.URL, signatures)
	if err != nil {
		return harnessx.Result{Observations: observations, Err: err}, nil
	}
	return harnessx.Result{Observations: observations}, nil
})
