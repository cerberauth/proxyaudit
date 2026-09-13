package cmd

import (
	"fmt"

	"github.com/cerberauth/harnessx"
	"github.com/cerberauth/harnessx/reporters"
	"github.com/cerberauth/proxyaudit/proxy"
	"github.com/cerberauth/proxyaudit/proxy/probebase"
	"github.com/cerberauth/proxyaudit/proxy/scanctx"
	cobrareportx "github.com/cerberauth/x/cobrax/reportx"
	"github.com/cerberauth/x/reportx/harnessreport"
	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel"
)

const scanOtelName = "github.com/cerberauth/proxyaudit/cmd/scan"

var engineNames = map[string]scanctx.ProxyEngine{
	"":        scanctx.EngineUnknown,
	"nginx":   scanctx.EngineNginx,
	"traefik": scanctx.EngineTraefik,
	"envoy":   scanctx.EngineEnvoy,
	"caddy":   scanctx.EngineCaddy,
	"haproxy": scanctx.EngineHAProxy,
}

func NewScanCmd() *cobra.Command {
	var (
		aggressive bool
		engineFlag string
	)

	scanCmd := &cobra.Command{
		Use:   "scan [url]",
		Short: "Scan a reverse proxy / API gateway for common misconfigurations",
		Long: `Scan runs every proxyaudit check against the target URL: TLS/transport,
HTTP security headers, client-IP/header trust boundaries, and information
disclosure via exposed management interfaces.

--aggressive threads harnessx.ScanContext.Aggressive through to checks, but
has no effect yet since v0.1 has no Agg-tier checks — it's wired through so
later milestones don't require a CLI change.

Use only against systems you own or have explicit written permission to test.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			engine, ok := engineNames[engineFlag]
			if !ok {
				return fmt.Errorf("unknown --engine %q (want one of: nginx, traefik, envoy, caddy, haproxy)", engineFlag)
			}

			ctx := cmd.Context()

			otelReporter, _ := reporters.NewOTelReporter(
				ctx,
				otel.Tracer(scanOtelName),
				telemetryx.GetMeterProvider().Meter(scanOtelName),
				reporters.WithPrefix("proxyaudit.scan"),
			)

			sinks, cleanup, err := cobrareportx.SinksFromFlags(cmd)
			if err != nil {
				return err
			}
			defer cleanup()

			showAllFindings, err := cobrareportx.ShowAllFindingsFromFlags(cmd)
			if err != nil {
				return err
			}

			checks, defs := proxy.AllChecks()

			reportxReporter := harnessreport.New(ctx, harnessreport.Config{
				ToolName:        name,
				ToolVersion:     toolVersion,
				Title:           "Reverse Proxy Security Scan",
				Sinks:           sinks,
				CheckDefs:       defs,
				ShowAllFindings: showAllFindings,
			})

			hxEngine := harnessx.New(
				harnessx.WithChecks(checks...),
				harnessx.WithReporters(otelReporter, reportxReporter),
			)

			scanTarget := scanctx.NewTarget(target, &scanctx.ScanContext{
				Engine:     engine,
				Aggressive: aggressive,
			})

			summary, err := hxEngine.Run(ctx, scanTarget)
			if err != nil {
				return &RuntimeError{err: fmt.Errorf("scanning: %w", err)}
			}

			if err := reportxReporter.Err(); err != nil {
				return &RuntimeError{err: fmt.Errorf("reporting: %w", err)}
			}

			// The shared HTTP fetch failing outright (DNS, connection
			// refused, TLS handshake failure, ...) means the target
			// couldn't be reached at all — every dependent check then
			// skips rather than erroring, which would otherwise look
			// exactly like "reached the target, found nothing".
			if fetchErr := sharedFetchErr(summary); fetchErr != nil {
				return &RuntimeError{err: fmt.Errorf("connecting to target: %w", fetchErr)}
			}

			if len(summary.Observations) > 0 {
				return errFindingsPresent
			}
			return nil
		},
	}

	scanCmd.Flags().BoolVar(&aggressive, "aggressive", false, "Enable Agg-tier checks (no effect in v0.1 — no Agg-tier checks exist yet)")
	scanCmd.Flags().StringVar(&engineFlag, "engine", "", "Hint the fronting proxy engine: nginx, traefik, envoy, caddy, or haproxy (optional, overrides auto-detection)")
	cobrareportx.RegisterFormatFlags(scanCmd)
	cobrareportx.RegisterTransportFlags(scanCmd)

	return scanCmd
}

// sharedFetchErr returns probe.http_fetch's underlying error, if any, by
// scanning summary.Results — the shared fetch stores its error on Result.Data
// rather than Result.Err (so dependent checks can Skip cleanly instead of
// erroring), which would otherwise make total unreachability
// indistinguishable from "reached the target, found nothing".
func sharedFetchErr(summary harnessx.ScanSummary) error {
	for _, r := range summary.Results {
		if r.CheckID != probebase.HTTPFetchCheckID {
			continue
		}
		if fetched, ok := harnessx.DataAs[*probebase.FetchResult](r); ok && fetched.Err != nil {
			return fetched.Err
		}
	}
	return nil
}

// RuntimeError marks an error as a runtime/connection failure (exit code 2)
// rather than "findings present" (exit code 1) — see Execute in root.go.
type RuntimeError struct{ err error }

func (e *RuntimeError) Error() string { return e.err.Error() }
func (e *RuntimeError) Unwrap() error { return e.err }

// errFindingsPresent is a sentinel used only to drive the process exit
// code (1) — its message is never shown, since the report itself has
// already been written to every configured sink by the time it's returned.
type errFindingsPresentType struct{}

func (errFindingsPresentType) Error() string { return "" }

var errFindingsPresent = errFindingsPresentType{}
