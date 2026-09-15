<div align="center">

# proxyaudit

**A reverse proxy / API gateway security scanner — TLS, HTTP security headers, header trust boundaries, and exposed management interfaces.**

[![Join Discord](https://img.shields.io/discord/1242773130137833493?label=Discord&style=for-the-badge)](https://www.cerberauth.com/community)
[![Build](https://img.shields.io/github/actions/workflow/status/cerberauth/proxyaudit/ci.yml?branch=main&label=build&style=for-the-badge)](https://github.com/cerberauth/proxyaudit/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/cerberauth/proxyaudit?sort=semver&style=for-the-badge)](https://github.com/cerberauth/proxyaudit/releases)
[![Coverage](https://img.shields.io/codecov/c/gh/cerberauth/proxyaudit?style=for-the-badge)](https://codecov.io/gh/cerberauth/proxyaudit)
[![GoDoc](https://img.shields.io/badge/godoc-reference-5272B4.svg?style=for-the-badge)](https://godoc.org/github.com/cerberauth/proxyaudit)
[![Stars](https://img.shields.io/github/stars/cerberauth/proxyaudit?style=for-the-badge)](https://github.com/cerberauth/proxyaudit)
[![License](https://img.shields.io/github/license/cerberauth/proxyaudit?style=for-the-badge)](https://github.com/cerberauth/proxyaudit/blob/main/LICENSE)

</div>

`proxyaudit` dynamically tests whether a reverse proxy or API gateway is
securely configured: TLS/transport, HTTP security headers, client-IP/header
trust boundaries, and information disclosure via exposed management
interfaces. Its check engine (`proxy/`) is built on
[`harnessx`](https://github.com/cerberauth/harnessx), the same check
orchestration library used by [VulnAPI](https://github.com/cerberauth/vulnapi)
and [jwtop](https://github.com/cerberauth/jwtop) — part of the
[CerberAuth](https://cerberauth.com) DAST portfolio.

## Install

<table>
<tr><td>

**go install**

```sh
go install github.com/cerberauth/proxyaudit@latest
```

</td><td>

**Homebrew**

```sh
brew install cerberauth/tap/proxyaudit
```

</td><td>

**Docker**

```sh
docker run --rm ghcr.io/cerberauth/proxyaudit scan <url>
```

</td></tr>
</table>

See the [installation guide](https://www.cerberauth.com/docs/proxyaudit/installation/)
for more options (Scoop, apt/yum/apk, Arch, Snap, winget, Chocolatey).

## Usage

```sh
proxyaudit scan https://proxy.example.com
```

```
Flags:
      --aggressive                     Enable Agg-tier checks (no effect in v0.1 — no Agg-tier checks exist yet)
      --engine string                  Hint the fronting proxy engine: nginx, traefik, envoy, caddy, or haproxy (optional, overrides auto-detection)
      --format string                  terminal display format (default "terminal")
      --no-color                       disable ANSI colors in terminal output
      --output string                  file path to additionally write the report to
      --output-format string           format for --output (default "json")
      --quiet                          suppress terminal display of the report
      --report-url string              HTTP endpoint to POST the report to
      --report-header stringToString   additional HTTP headers for the report transport (key=value)
      --report-format string           format for --report-url (default "json")
      --show-all-findings              show every finding on stdout, not just vulnerable ones
```

Exit codes: `0` no findings, `1` findings present, `2` runtime/connection
error — standard for CI usage. See the [GitHub Actions guide](https://www.cerberauth.com/docs/proxyaudit/github-actions/)
for CI examples.

Every check is non-destructive and read-only (single or few requests, no
brute-forcing or state mutation). Use only against systems you own or have
explicit written permission to test.

## Checks (v0.1)

See the [checks reference](https://www.cerberauth.com/docs/proxyaudit/checks/)
for the full list with CWE/OWASP mapping and remediation.

- **TLS/Transport**: protocol version, cipher strength/forward secrecy,
  certificate chain/expiry/hostname/OCSP stapling, HTTP→HTTPS redirect, HSTS.
- **HTTP Security Headers**: CSP, X-Frame-Options/frame-ancestors,
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy, Server/
  X-Powered-By banner disclosure, cookie flags.
- **Client-IP & Header Trust Boundary**: X-Forwarded-For, X-Real-IP,
  True-Client-IP, X-Forwarded-Host reflection, Host header injection,
  virtual-host confusion via a crafted Host header, RFC 7239 `Forwarded` vs.
  legacy header consistency, and IP-based access control bypass via a
  spoofed client-IP header.
- **Information Disclosure & Exposed Management Interfaces**: verbose error
  pages, exposed proxy admin/status interfaces (Traefik, HAProxy, Envoy,
  nginx, Apache), directory listing, config/secrets file exposure.

## Documentation

Full documentation, including installation options, the CLI reference, the
checks reference, and CI/Docker guides, is at
[cerberauth.com/docs/proxyaudit](https://www.cerberauth.com/docs/proxyaudit).

## Contributing

Issues and pull requests are welcome. Run the test suite with:

```sh
go build ./...
go vet ./...
go test ./...
```

## License

MIT — see [LICENSE](./LICENSE).
