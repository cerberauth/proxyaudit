// Package smuggling_test exercises the checks/smuggling scanners against a
// raw TCP server (net/http's own server rewrites malformed framing, so a
// hand-rolled listener is needed to model a proxy that accepts or rejects
// it) driven through a harnessx.Engine as proxyaudit would.
package smuggling_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cerberauth/harnessx"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ambiguousframing "github.com/cerberauth/proxyaudit/proxy/checks/smuggling/ambiguous_framing"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
)

// behaviour decides how the stub proxy answers a raw request.
type behaviour func(raw string) int

// permissive accepts everything.
func permissive(string) int { return http.StatusOK }

// strict rejects RFC-violating ambiguous framing, accepts the rest —
// a conformant proxy.
func strict(raw string) int {
	lower := strings.ToLower(raw)
	switch {
	case strings.Count(lower, "content-length:") >= 2,
		strings.Contains(lower, "content-length:") && strings.Contains(lower, "transfer-encoding"),
		strings.Count(lower, "transfer-encoding") >= 2,
		strings.Contains(raw, "Transfer-Encoding :"):
		return http.StatusBadRequest
	}
	return http.StatusOK
}

// rejectAll models an endpoint that 400s even a well-formed request.
func rejectAll(string) int { return http.StatusBadRequest }

// rawServer serves one response per connection, its status chosen by fn
// after reading the request bytes.
func rawServer(t *testing.T, fn behaviour) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetReadDeadline(time.Now().Add(time.Second))
				// The whole request arrives in one write before the client
				// reads, so one Read returns it — no need to drain to EOF
				// (the client holds the connection open) and wait out the
				// deadline.
				buf := make([]byte, 8192)
				n, _ := c.Read(buf)
				code := fn(string(buf[:n]))
				body := "OK"
				_, _ = fmt.Fprintf(c, "HTTP/1.1 %d %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
					code, http.StatusText(code), len(body), body)
			}(conn)
		}
	}()
	return "http://" + ln.Addr().String()
}

func run(t *testing.T, url string, aggressive bool) harnessx.ScanSummary {
	t.Helper()
	target := scanctx.NewTarget(url, &scanctx.ScanContext{HTTPClient: http.DefaultClient, Aggressive: aggressive})
	engine := harnessx.New(harnessx.WithChecks(probebase.HTTPFetchCheck, ambiguousframing.Check))
	summary, err := engine.Run(context.Background(), target)
	require.NoError(t, err)
	return summary
}

func TestAmbiguousFraming_PermissiveProxy_FlagsEveryVariant(t *testing.T) {
	summary := run(t, rawServer(t, permissive), true)
	variants := map[string]bool{}
	for _, o := range summary.Observations {
		variants[o.Metadata["variant"]] = true
	}
	for _, want := range []string{"duplicate_content_length", "cl_te", "te_obfuscated_value", "te_obfuscated_name"} {
		assert.True(t, variants[want], "expected variant %q flagged, got %v", want, variants)
	}
}

func TestAmbiguousFraming_StrictProxy_NoFindings(t *testing.T) {
	assert.Empty(t, run(t, rawServer(t, strict), true).Observations)
}

func TestAmbiguousFraming_EndpointRejectsBaseline_Skipped(t *testing.T) {
	summary := run(t, rawServer(t, rejectAll), true)
	assert.Empty(t, summary.Observations)
	assert.True(t, skipped(summary))
}

func TestAmbiguousFraming_NotAggressive_Skipped(t *testing.T) {
	summary := run(t, rawServer(t, permissive), false)
	assert.Empty(t, summary.Observations)
	assert.True(t, skipped(summary))
}

func skipped(summary harnessx.ScanSummary) bool {
	for _, r := range summary.Results {
		if r.CheckID == ambiguousframing.Check.ID {
			return r.Skipped
		}
	}
	return false
}
