package cmd

import (
	"fmt"

	"github.com/salamancacm/vpsguard/internal/selfupdate"
	"github.com/salamancacm/vpsguard/internal/system"
	"github.com/spf13/cobra"
)

var updateCheckOnly bool

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update vpsguard to the latest release",
	Long: "Checks GitHub for a newer release and, unless --check is given,\n" +
		"downloads and installs it in place. Never runs automatically —\n" +
		"this is always an explicit, operator-triggered command, same as\n" +
		"'harden' requiring --yes/confirmation.",
	RunE: func(cmd *cobra.Command, args []string) error {
		requireLinux()

		latest, err := selfupdate.LatestTag()
		if err != nil {
			return err
		}

		if !selfupdate.IsNewer(Version, latest) {
			fmt.Printf("vpsguard is up to date (%s)\n", Version)
			return nil
		}

		fmt.Printf("a newer version is available: %s -> %s\n", Version, latest)

		if updateCheckOnly {
			fmt.Println("run 'vpsguard update' (without --check) to install it")
			return nil
		}

		if !system.IsRoot() {
			return fmt.Errorf("update must run as root (use sudo) to replace the installed binary")
		}

		fmt.Println("downloading and verifying...")
		if err := selfupdate.Apply(); err != nil {
			return err
		}
		fmt.Printf("updated to %s\n", latest)
		return nil
	},
}

func init() {
	updateCmd.Flags().BoolVar(&updateCheckOnly, "check", false, "only report whether an update is available, don't install it")
	rootCmd.AddCommand(updateCmd)
}
