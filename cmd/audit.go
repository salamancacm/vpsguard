package cmd

import (
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

		findings := checks.Run(names)

		if jsonOutput {
			return report.PrintJSON(os.Stdout, findings)
		}
		report.PrintTable(os.Stdout, findings)
		return nil
	},
}

func init() {
	auditCmd.Flags().StringVar(&auditCheckFilter, "check", "", "comma-separated list of checks to run (e.g. ssh,firewall)")
	rootCmd.AddCommand(auditCmd)
}
