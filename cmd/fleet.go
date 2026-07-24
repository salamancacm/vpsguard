package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/salamancacm/vpsguard/internal/config"
	"github.com/salamancacm/vpsguard/internal/fleet"
	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/spf13/cobra"
)

var (
	fleetConfigPath  string
	fleetConcurrency int
)

var fleetCmd = &cobra.Command{
	Use:   "fleet",
	Short: "Audit multiple hosts over SSH and report an aggregated summary",
	Long: "Runs 'vpsguard audit --json' on each host listed under 'hosts:' in\n" +
		"the config file (see --config) and aggregates the results. Connects\n" +
		"using your existing SSH setup (keys, agent, ~/.ssh/config) — vpsguard\n" +
		"never handles credentials itself. vpsguard must already be installed\n" +
		"on every target host.",
	RunE: func(cmd *cobra.Command, args []string) error {
		cfg, err := config.Load(fleetConfigPath)
		if err != nil {
			return err
		}
		if len(cfg.Hosts) == 0 {
			return fmt.Errorf("no hosts configured — add a 'hosts:' list to %s", fleetConfigPath)
		}

		results := fleet.Run(cfg.Hosts, fleetConcurrency)

		if jsonOutput {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			return enc.Encode(results)
		}

		printFleetResults(results)
		return nil
	},
}

func printFleetResults(results []fleet.HostResult) {
	var allFindings []report.Finding
	unreachable := 0

	for _, r := range results {
		report.PrintCheckHeader(os.Stdout, r.Host)
		if r.Error != "" {
			fmt.Printf("  error: %s\n", r.Error)
			unreachable++
		} else {
			report.PrintFindings(os.Stdout, r.Findings)
			allFindings = append(allFindings, r.Findings...)
		}
		fmt.Println()
	}

	fmt.Printf("Fleet: %d host(s), %d unreachable\n", len(results), unreachable)
	report.PrintSummary(os.Stdout, allFindings)
}

func init() {
	fleetCmd.Flags().StringVar(&fleetConfigPath, "config", config.DefaultPath, "path to vpsguard's config file (must list 'hosts:')")
	fleetCmd.Flags().IntVar(&fleetConcurrency, "concurrency", 5, "maximum number of hosts to audit at once")
	rootCmd.AddCommand(fleetCmd)
}
