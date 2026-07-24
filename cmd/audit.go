package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/salamancacm/vpsguard/internal/checks"
	"github.com/salamancacm/vpsguard/internal/config"
	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/spf13/cobra"
)

var (
	auditCheckFilter string
	auditConfigPath  string
)

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit the server's security posture (read-only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		requireLinux()

		cfg, err := config.Load(auditConfigPath)
		if err != nil {
			return err
		}
		applyThresholds(cfg)

		var requested []string
		if auditCheckFilter != "" {
			requested = strings.Split(auditCheckFilter, ",")
		}
		names := cfg.FilterDisabled(requested, checks.Order)

		if jsonOutput {
			findings := cfg.MarkAccepted(runChecks(names))
			return report.PrintJSON(os.Stdout, findings)
		}

		if report.Interactive() {
			runAuditInteractive(names, cfg)
			return nil
		}

		findings := cfg.MarkAccepted(runChecks(names))
		report.PrintTable(os.Stdout, findings)
		return nil
	},
}

// runChecks runs exactly the given check names, in order. Unlike
// checks.Run, an empty list here means "run nothing" — names is always
// already fully resolved by config.Config.FilterDisabled (which applies
// the "no --check filter means everything" default itself), so there's no
// ambiguity to paper over, including the edge case of every check having
// been disabled via config.
func runChecks(names []string) []report.Finding {
	var all []report.Finding
	for _, name := range names {
		if fn, ok := checks.All[name]; ok {
			all = append(all, fn()...)
		}
	}
	return all
}

// runAuditInteractive announces each check right before it runs and prints
// its findings immediately, instead of going quiet until everything is
// done — checks.Run already takes a couple of seconds since it shells out
// to real system tools, so this is a truthful reflection of progress, not
// an artificial spinner. Only used when stdout is a real terminal; piped
// or --json output always gets the plain, stable format from checks.Run.
func runAuditInteractive(names []string, cfg config.Config) {
	var all []report.Finding
	for _, name := range names {
		fn, ok := checks.All[name]
		if !ok {
			continue
		}
		report.PrintCheckHeader(os.Stdout, name)
		findings := cfg.MarkAccepted(fn())
		report.PrintFindings(os.Stdout, findings)
		all = append(all, findings...)
		fmt.Println()
	}

	report.PrintSummary(os.Stdout, all)
}

// applyThresholds overrides internal/checks' package-level threshold vars
// from config, if set (0 means "use the built-in default", left alone).
func applyThresholds(cfg config.Config) {
	if cfg.Thresholds.Kernel.SecurityUpdateWarn != 0 {
		checks.SecurityUpdateWarnThreshold = cfg.Thresholds.Kernel.SecurityUpdateWarn
	}
	if cfg.Thresholds.Kernel.SecurityUpdateCrit != 0 {
		checks.SecurityUpdateCritThreshold = cfg.Thresholds.Kernel.SecurityUpdateCrit
	}
}

func init() {
	auditCmd.Flags().StringVar(&auditCheckFilter, "check", "", "comma-separated list of checks to run (e.g. ssh,firewall)")
	auditCmd.Flags().StringVar(&auditConfigPath, "config", config.DefaultPath, "path to vpsguard's config file")
	rootCmd.AddCommand(auditCmd)
}
