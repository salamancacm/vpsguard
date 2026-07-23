package harden

// FixFunc applies remediation for one check category. dryRun=true must not
// modify anything and instead describe what it would do.
type FixFunc func(dryRun bool) ([]string, error)

// All maps check names (matching internal/checks.All) to their remediation.
// Only checks with an automatable, safe fix are listed here — "users",
// "cron" and "network" require human judgement and are audit-only.
var All = map[string]FixFunc{
	"ssh":      SSH,
	"firewall": Firewall,
	"fail2ban": Fail2ban,
	"sshkeys":  SSHKeys,
	"updates":  Updates,
}

// Order is the canonical, human-friendly ordering of fixable check names.
var Order = []string{"ssh", "firewall", "fail2ban", "sshkeys", "updates"}
