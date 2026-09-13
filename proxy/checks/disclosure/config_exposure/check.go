// Package configexposure probes a fixed list of config-adjacent paths for
// content that looks like configuration or secrets, rather than the
// backend's ordinary (missing-route) response.
package configexposure

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

var Def = checkdef.MustParseCheckDefYAML("config_exposure", checkYAML)

func contains(body []byte, markers ...string) bool {
	for _, m := range markers {
		if bytes.Contains(body, []byte(m)) {
			return true
		}
	}
	return false
}

func configLike(status int, _ http.Header, body []byte) bool {
	return status == http.StatusOK && contains(body,
		"server {", "location /", "upstream ", // nginx.conf
		"<VirtualHost", "DocumentRoot", // apache/web.config-ish
		"version:", "services:", "image:", // docker-compose.yml
		"[core]", "[remote ", // .git/config
	)
}

func envLike(status int, _ http.Header, body []byte) bool {
	if status != http.StatusOK {
		return false
	}
	return contains(body, "SECRET", "PASSWORD", "API_KEY", "DATABASE_URL", "_KEY=", "_TOKEN=")
}

var signatures = []probebase.PathSignature{
	{
		Path:        "/.env",
		Title:       "Environment file (.env) exposed",
		Description: "The .env path returned content resembling environment variables (secrets, credentials, or API keys), rather than a 404.",
		Match:       envLike,
	},
	{
		Path:        "/nginx.conf",
		Title:       "nginx.conf exposed",
		Description: "The nginx.conf path returned content resembling an nginx configuration file, exposing internal routing and backend details.",
		Match:       configLike,
	},
	{
		Path:        "/docker-compose.yml",
		Title:       "docker-compose.yml exposed",
		Description: "The docker-compose.yml path returned content resembling a Compose file, exposing service topology and possibly embedded secrets.",
		Match:       configLike,
	},
	{
		Path:        "/web.config",
		Title:       "web.config exposed",
		Description: "The web.config path returned content resembling an IIS configuration file.",
		Match:       configLike,
	},
	{
		Path:        "/.git/config",
		Title:       ".git/config exposed",
		Description: "The .git/config path returned content resembling a Git config file, indicating an exposed .git directory that may allow full source reconstruction.",
		Match:       configLike,
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
