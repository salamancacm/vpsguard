// Package cmd implements the vpsguard CLI: audit, harden, monitor and
// install-cron subcommands built on cobra.
package cmd

import (
	"fmt"
	"os"
	"runtime"

	"github.com/salamancacm/vpsguard/internal/system"
	"github.com/spf13/cobra"
)

var (
	jsonOutput bool
)

// Version is set at build time via -ldflags "-X .../cmd.Version=vX.Y.Z".
// Left as "dev" for local builds.
var Version = "dev"

var rootCmd = &cobra.Command{
	Use:           "vpsguard",
	Short:         "Security audit, hardening, and monitoring for Linux VPS",
	Version:       Version,
	SilenceUsage:  true,
	SilenceErrors: false,
}

// Execute runs the CLI. Called from main.go.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output as JSON instead of a table")
}

// requireLinux exits with a clear message if not running on Linux, since
// every check/harden action shells out to Linux-specific tools.
func requireLinux() {
	if system.IsLinux() {
		return
	}
	fmt.Fprintf(os.Stderr, "vpsguard only works on Linux (detected: %s)\n", runtime.GOOS)
	os.Exit(1)
}
