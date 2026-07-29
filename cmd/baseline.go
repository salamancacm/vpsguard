package cmd

import (
	"fmt"

	"github.com/salamancacm/vpsguard/internal/snapshot"
	"github.com/salamancacm/vpsguard/internal/system"
	"github.com/spf13/cobra"
)

var baselineCmd = &cobra.Command{
	Use:   "baseline",
	Short: "Pin the current state of watched critical binaries as the trusted reference for 'monitor'",
	Long: "Hashes vpsguard's watched critical binaries (sshd, sudo, su, ssh) and saves them\n" +
		"as a fixed baseline in " + snapshot.StoreDir + ".\n\n" +
		"'vpsguard monitor' already compares each run against the previous one, but that\n" +
		"alone can miss a binary that's swapped back and forth across runs, or\n" +
		"re-compromised right after each check. A pinned baseline catches that: once set,\n" +
		"every future 'monitor' run also compares against it, and keeps flagging a\n" +
		"mismatch until it's fixed and 'vpsguard baseline' is run again.\n\n" +
		"Run this again after 'vpsguard harden', 'vpsguard update', or any legitimate\n" +
		"package upgrade that touches a watched binary — otherwise the next 'monitor' run\n" +
		"will (correctly) report it as changed.",
	RunE: func(cmd *cobra.Command, args []string) error {
		requireLinux()
		if !system.IsRoot() {
			return fmt.Errorf("baseline must run as root (use sudo)")
		}

		cur := snapshot.Capture()
		if err := snapshot.SaveBaseline(cur); err != nil {
			return fmt.Errorf("saving baseline: %w", err)
		}

		fmt.Printf("baseline set: %d binaries pinned as the trusted reference\n", snapshot.WatchedBinaryCount(cur))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(baselineCmd)
}
