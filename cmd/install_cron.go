package cmd

import (
	"fmt"
	"os"

	"github.com/salamancacm/vpsguard/internal/system"
	"github.com/spf13/cobra"
)

const cronDropinPath = "/etc/cron.d/vpsguard"

var installCronInterval string

var installCronCmd = &cobra.Command{
	Use:   "install-cron",
	Short: "Install a cron entry that runs 'vpsguard monitor' periodically",
	RunE: func(cmd *cobra.Command, args []string) error {
		requireLinux()
		if !system.IsRoot() {
			return fmt.Errorf("install-cron must run as root (use sudo)")
		}

		binPath, err := os.Executable()
		if err != nil {
			return fmt.Errorf("could not determine the binary's path: %w", err)
		}

		line := fmt.Sprintf("%s root %s monitor >> /var/log/vpsguard-monitor.log 2>&1\n",
			installCronInterval, binPath)

		fmt.Printf("This will write %s with:\n\n  %s\n", cronDropinPath, line)
		if !confirm("Install this cron entry?") {
			fmt.Println("cancelled")
			return nil
		}

		if err := os.WriteFile(cronDropinPath, []byte(line), 0o644); err != nil {
			return fmt.Errorf("writing %s: %w", cronDropinPath, err)
		}
		fmt.Println("installed:", cronDropinPath)
		return nil
	},
}

func init() {
	installCronCmd.Flags().StringVar(&installCronInterval, "schedule", "*/15 * * * *", "cron expression for how often 'monitor' runs")
	rootCmd.AddCommand(installCronCmd)
}
