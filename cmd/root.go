package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/cerberauth/x/telemetryx"
	"github.com/spf13/cobra"
)

var (
	sqaOptOut    bool
	otelShutdown func(context.Context) error
	toolVersion  string
)

var name = "proxyaudit"

func NewRootCmd(projectVersion, commit, date string) (cmd *cobra.Command) {
	toolVersion = projectVersion
	var rootCmd = &cobra.Command{
		Use:           name,
		Version:       projectVersion + " (commit=" + commit + ", built=" + date + ")",
		Short:         "Reverse proxy / API gateway security scanner",
		Long:          `proxyaudit dynamically tests whether a reverse proxy or API gateway is securely configured: TLS/transport, HTTP security headers, client-IP/header trust boundaries, and information disclosure via exposed management interfaces.`,
		SilenceErrors: true,
		SilenceUsage:  true,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !sqaOptOut {
				otelShutdown, _ = telemetryx.New(cmd.Context(), name, projectVersion, telemetryx.WithCommit(commit), telemetryx.WithBuildDate(date))
			}
		},
		PersistentPostRun: func(cmd *cobra.Command, args []string) {
			if otelShutdown != nil {
				_ = otelShutdown(cmd.Context())
				otelShutdown = nil
			}
		},
	}

	rootCmd.AddCommand(NewScanCmd())

	rootCmd.PersistentFlags().BoolVarP(&sqaOptOut, "sqa-opt-out", "", false, "Opt out of sending anonymous usage statistics and crash reports to help improve the tool")

	return rootCmd
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the RootCmd.
func Execute(projectVersion, commit, date string) {
	c := NewRootCmd(projectVersion, commit, date)
	defer func() {
		if otelShutdown != nil {
			_ = otelShutdown(context.Background())
			otelShutdown = nil
		}
	}()

	if err := c.Execute(); err != nil {
		if otelShutdown != nil {
			_ = otelShutdown(context.Background())
			otelShutdown = nil
		}

		// errFindingsPresent (scan.go) carries no message — the report
		// was already written to every configured sink by the time it's
		// returned, so there's nothing left to print here.
		if err.Error() != "" {
			fmt.Fprintln(os.Stderr, err)
		}

		var runtimeErr *RuntimeError
		if errors.As(err, &runtimeErr) {
			os.Exit(2) //nolint:gocritic // otelShutdown was already run explicitly above, not relying on the deferred call
		}
		os.Exit(1) //nolint:gocritic // otelShutdown was already run explicitly above, not relying on the deferred call
	}
}
