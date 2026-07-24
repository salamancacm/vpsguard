package cmd

import (
	"fmt"
	"os"

	"github.com/salamancacm/vpsguard/internal/config"
	"github.com/salamancacm/vpsguard/internal/notify"
	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/snapshot"
	"github.com/salamancacm/vpsguard/internal/system"
	"github.com/spf13/cobra"
)

var monitorConfigPath string

var monitorCmd = &cobra.Command{
	Use:   "monitor",
	Short: "Compare current state against the last snapshot and report suspicious changes",
	Long: "Meant to run periodically via cron (see 'vpsguard install-cron').\n" +
		"Each run compares users, SSH keys, cron, and ports against the previous\n" +
		"snapshot saved in " + snapshot.StoreDir + " and reports what changed.\n" +
		"If " + config.DefaultPath + " configures a webhook_url or email_to,\n" +
		"changes are also pushed out there — see the README's notifications section.",
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
			if err := report.PrintJSON(os.Stdout, findings); err != nil {
				return err
			}
		} else if len(findings) == 0 {
			fmt.Println("no suspicious changes since the last run")
		} else {
			report.PrintTable(os.Stdout, findings)
		}

		sendNotifications(findings)
		return nil
	},
}

// sendNotifications pushes findings to whatever's configured in
// config.DefaultPath (or --config). Errors here are printed as warnings,
// never returned as a command failure — a broken webhook must not make
// `monitor` look like it failed to do its actual job.
func sendNotifications(findings []report.Finding) {
	if len(findings) == 0 {
		return
	}

	cfg, err := config.Load(monitorConfigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: %v\n", err)
		return
	}

	var notifiers []notify.Notifier
	if cfg.Notify.WebhookURL != "" {
		notifiers = append(notifiers, notify.NewWebhookNotifier(cfg.Notify.WebhookURL))
	}
	if cfg.Notify.EmailTo != "" {
		notifiers = append(notifiers, notify.NewEmailNotifier(cfg.Notify.EmailTo))
	}
	if len(notifiers) == 0 {
		return
	}

	toSend := notify.Filter(findings, notify.ParseMinSeverity(cfg.Notify.MinSeverity))
	if len(toSend) == 0 {
		return
	}

	for _, n := range notifiers {
		if err := n.Notify(toSend); err != nil {
			fmt.Fprintf(os.Stderr, "warning: notification failed: %v\n", err)
		}
	}
}

func init() {
	monitorCmd.Flags().StringVar(&monitorConfigPath, "config", config.DefaultPath, "path to vpsguard's config file")
	rootCmd.AddCommand(monitorCmd)
}
