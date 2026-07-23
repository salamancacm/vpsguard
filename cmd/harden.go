package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/salamancacm/vpsguard/internal/harden"
	"github.com/salamancacm/vpsguard/internal/system"
	"github.com/spf13/cobra"
)

var (
	hardenDryRun      bool
	hardenYes         bool
	hardenCheckFilter string
)

var hardenCmd = &cobra.Command{
	Use:   "harden",
	Short: "Apply security remediations (SSH, firewall, fail2ban, permissions, updates)",
	RunE: func(cmd *cobra.Command, args []string) error {
		requireLinux()

		if !hardenDryRun && !system.IsRoot() {
			return fmt.Errorf("harden must run as root (use sudo), or pass --dry-run to see what it would do")
		}

		names := harden.Order
		if hardenCheckFilter != "" {
			names = strings.Split(hardenCheckFilter, ",")
		}

		for _, name := range names {
			fn, ok := harden.All[name]
			if !ok {
				fmt.Printf("skip: '%s' has no automatic remediation\n", name)
				continue
			}

			if !hardenDryRun && !hardenYes {
				if !confirm(fmt.Sprintf("Apply hardening for '%s'?", name)) {
					fmt.Printf("skipped: %s\n\n", name)
					continue
				}
			}

			fmt.Printf("== %s ==\n", name)
			applied, err := fn(hardenDryRun)
			for _, line := range applied {
				fmt.Println("  " + line)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "  error: %v\n", err)
			}
			fmt.Println()
		}

		return nil
	},
}

func confirm(prompt string) bool {
	fmt.Printf("%s [y/N]: ", prompt)
	reader := bufio.NewReader(os.Stdin)
	answer, _ := reader.ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes"
}

func init() {
	hardenCmd.Flags().BoolVar(&hardenDryRun, "dry-run", false, "show what would happen without changing anything")
	hardenCmd.Flags().BoolVar(&hardenYes, "yes", false, "apply everything without asking for per-step confirmation")
	hardenCmd.Flags().StringVar(&hardenCheckFilter, "check", "", "comma-separated list of checks to apply (e.g. ssh,firewall)")
	rootCmd.AddCommand(hardenCmd)
}
