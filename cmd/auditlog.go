package cmd

import (
	"fmt"

	"github.com/salamancacm/vpsguard/internal/auditlog"
	"github.com/spf13/cobra"
)

var auditlogCmd = &cobra.Command{
	Use:   "auditlog",
	Short: "Inspect the append-only log of 'monitor' runs",
}

var auditlogVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Recompute the audit log's hash chain and report whether it's intact",
	Long: "Every 'vpsguard monitor' run appends one entry to " + auditlog.Path() + ",\n" +
		"chained to the entry before it. Editing, deleting, or reordering any past\n" +
		"entry -- including the most recent one -- breaks the chain from that point\n" +
		"on, which this command detects.\n\n" +
		"This can't, by itself, catch a wholesale replacement of the entire log by\n" +
		"an attacker with root -- they can regenerate a new, internally-consistent\n" +
		"chain from scratch. If you suspect that, compare this run's last hash\n" +
		"against one you saved off-host from an earlier 'auditlog verify' run.",
	RunE: func(cmd *cobra.Command, args []string) error {
		requireLinux()

		result, err := auditlog.Verify()
		if err != nil {
			return fmt.Errorf("verifying audit log: %w", err)
		}

		if result.EntryCount == 0 {
			fmt.Println("audit log is empty (no 'monitor' runs yet)")
			return nil
		}

		if !result.OK {
			fmt.Printf("TAMPERED: chain breaks at seq %d: %s\n", result.BrokenAtSeq, result.Reason)
			return fmt.Errorf("audit log integrity check failed")
		}

		entries, err := auditlog.Load()
		if err != nil {
			return err
		}
		last := entries[len(entries)-1]
		fmt.Printf("OK: %d entries verified, chain intact\n", result.EntryCount)
		fmt.Printf("last entry: seq=%d timestamp=%s hash=%s\n", last.Seq, last.Timestamp.Format("2006-01-02T15:04:05Z"), last.Hash)
		return nil
	},
}

func init() {
	auditlogCmd.AddCommand(auditlogVerifyCmd)
	rootCmd.AddCommand(auditlogCmd)
}
