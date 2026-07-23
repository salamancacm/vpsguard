package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/salamancacm/vpsguard/internal/checks"
	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/spf13/cobra"
)

var auditCheckFilter string

var auditCmd = &cobra.Command{
	Use:   "audit",
	Short: "Audit the server's security posture (read-only)",
	RunE: func(cmd *cobra.Command, args []string) error {
		requireLinux()

		var names []string
		if auditCheckFilter != "" {
			names = strings.Split(auditCheckFilter, ",")
		}

		if jsonOutput {
			return report.PrintJSON(os.Stdout, checks.Run(names))
		}

		if report.Interactive() {
			runAuditInteractive(names)
			return nil
		}

		report.PrintTable(os.Stdout, checks.Run(names))
		return nil
	},
}

// runAuditInteractive announces each check right before it runs and prints
// its findings immediately, instead of going quiet until everything is
// done — checks.Run already takes a couple of seconds since it shells out
// to real system tools, so this is a truthful reflection of progress, not
// an artificial spinner. Only used when stdout is a real terminal; piped
// or --json output always gets the plain, stable format from checks.Run.
func runAuditInteractive(names []string) {
	selected := checks.Order
	if len(names) > 0 {
		selected = names
	}

	var all []report.Finding
	for _, name := range selected {
		fn, ok := checks.All[name]
		if !ok {
			continue
		}
		report.PrintCheckHeader(os.Stdout, name)
		findings := fn()
		report.PrintFindings(os.Stdout, findings)
		all = append(all, findings...)
		fmt.Println()
	}

	report.PrintSummary(os.Stdout, all)
}

func init() {
	auditCmd.Flags().StringVar(&auditCheckFilter, "check", "", "comma-separated list of checks to run (e.g. ssh,firewall)")
	rootCmd.AddCommand(auditCmd)
}
