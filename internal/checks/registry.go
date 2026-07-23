package checks

import "github.com/salamancacm/vpsguard/internal/report"

// CheckFunc runs a single audit category and returns its findings.
type CheckFunc func() []report.Finding

// All maps check names (used with --check=name,name) to their implementation.
// Order here also controls the order findings are printed in.
var All = map[string]CheckFunc{
	"ssh":      SSH,
	"firewall": Firewall,
	"fail2ban": Fail2ban,
	"users":    Users,
	"sshkeys":  SSHKeys,
	"cron":     Cron,
	"updates":  Updates,
	"network":  Network,
	"docker":   Docker,
}

// Order is the canonical, human-friendly ordering of check names.
var Order = []string{"ssh", "firewall", "fail2ban", "users", "sshkeys", "cron", "updates", "network", "docker"}

// Run executes the given check names (or all of them if names is empty) and
// returns the combined findings in canonical order.
func Run(names []string) []report.Finding {
	selected := Order
	if len(names) > 0 {
		selected = names
	}

	var findings []report.Finding
	for _, name := range selected {
		fn, ok := All[name]
		if !ok {
			continue
		}
		findings = append(findings, fn()...)
	}
	return findings
}
