package cmd

import (
	"fmt"
	"os"

	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/snapshot"
	"github.com/salamancacm/vpsguard/internal/system"
	"github.com/spf13/cobra"
)

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Compare current state against the last snapshot and report suspicious changes",
	Long: "Meant to run periodically via cron (see 'vpsguard install-cron').\n" +
		"Each run compares users, SSH keys, cron, and ports against the previous\n" +
		"snapshot saved in " + snapshot.StoreDir + " and reports what changed.",
	RunE: func(cmd *cobra.Command, args []string) error {
		requireLinux()
		if !system.IsRoot() {
			return fmt.Errorf("monitor must run as root (use sudo)")
		}

		cur := snapshot.Capture()
		old, hadPrevious, err := snapshot.Load()
		if err != nil {
			return fmt.Errorf("reading previous snapshot: %w", err)
		}

		if err := snapshot.Save(cur); err != nil {
			return fmt.Errorf("saving snapshot: %w", err)
		}

		if !hadPrevious {
			fmt.Println("first snapshot saved, nothing to compare against yet")
			return nil
		}

		findings := snapshot.Diff(old, cur)

		if jsonOutput {
			return report.PrintJSON(os.Stdout, findings)
		}

		if len(findings) == 0 {
			fmt.Println("no suspicious changes since the last run")
			return nil
		}
		report.PrintTable(os.Stdout, findings)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(monitorCmd)
}
