package cmd

import (
	"fmt"
	"os"

	"github.com/salamancacm/vpsguard/internal/checks"
	"github.com/salamancacm/vpsguard/internal/config"
	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/snapshot"
	"github.com/salamancacm/vpsguard/internal/system"
	"github.com/spf13/cobra"
)

var initConfigPath string

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Guided first-run setup: audit, optionally harden, pin a binary baseline, and install monitoring",
	Long: "Walks through vpsguard's usual first-run steps in one guided flow instead of\n" +
		"four separate commands run by hand: 'audit' to see where the server stands,\n" +
		"then offers to run 'harden' (the normal per-check confirmation, nothing new),\n" +
		"pin a 'baseline' for tamper detection, and install the 'monitor' cron entry.\n" +
		"Every step past the initial audit needs an explicit yes -- 'init' itself\n" +
		"never applies a change silently, it just walks you to the prompt.",
	RunE: func(cmd *cobra.Command, args []string) error {
		requireLinux()
		if !system.IsRoot() {
			return fmt.Errorf("init must run as root (use sudo)")
		}

		cfg, err := config.Load(initConfigPath)
		if err != nil {
			return err
		}
		applyThresholds(cfg)

		fmt.Println("== Step 1/4: audit ==")
		findings := cfg.MarkAccepted(runChecks(checks.Order))
		report.PrintTable(os.Stdout, findings)
		fmt.Println()

		fmt.Println("== Step 2/4: harden ==")
		if confirm("Walk through applying fixes now?") {
			hardenConfigPath = initConfigPath
			if err := hardenCmd.RunE(hardenCmd, nil); err != nil {
				fmt.Fprintf(os.Stderr, "warning: harden step failed: %v\n", err)
			}
		} else {
			fmt.Println("skipped -- run 'vpsguard harden' later")
		}
		fmt.Println()

		fmt.Println("== Step 3/4: pin a binary baseline ==")
		if confirm("Pin the current state of watched critical binaries as the trusted reference?") {
			if err := baselineCmd.RunE(baselineCmd, nil); err != nil {
				fmt.Fprintf(os.Stderr, "warning: baseline step failed: %v\n", err)
			}
		} else {
			fmt.Println("skipped -- run 'vpsguard baseline' later")
		}
		fmt.Println()

		fmt.Println("== Step 4/4: install the monitor cron ==")
		if confirm(fmt.Sprintf("Move on to installing a cron entry that runs 'monitor' every %s?", installCronInterval)) {
			if err := installCronCmd.RunE(installCronCmd, nil); err != nil {
				fmt.Fprintf(os.Stderr, "warning: install-cron step failed: %v\n", err)
			}
		} else {
			fmt.Println("skipped -- run 'vpsguard install-cron' later")
		}

		fmt.Println("\ndone. Snapshots and the baseline live in " + snapshot.StoreDir +
			"; edit " + config.DefaultPath + " to wire up notifications (see the README).")
		return nil
	},
}

func init() {
	initCmd.Flags().StringVar(&initConfigPath, "config", config.DefaultPath, "path to vpsguard's config file")
	rootCmd.AddCommand(initCmd)
}
