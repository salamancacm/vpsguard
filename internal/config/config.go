// Package config loads vpsguard's optional configuration file. Today it
// only covers notification settings for `vpsguard monitor` — broader
// config (disabled checks, custom thresholds, accepted findings) is a
// separate, larger piece of work.
package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// DefaultPath is where vpsguard looks for a config file if none is given
// explicitly. Its absence is not an error — every field is optional.
const DefaultPath = "/etc/vpsguard/config.yaml"

// Config is vpsguard's on-disk configuration.
type Config struct {
	Notify NotifyConfig `yaml:"notify"`

	// DisabledChecks skips these checks entirely in `audit` and `harden` —
	// equivalent to never passing them to --check.
	DisabledChecks []string `yaml:"disabled_checks"`

	// AcceptedFindings marks matching findings as acknowledged instead of
	// hiding them: they still print (with an [ACK] tag) and still appear
	// in --json (severity untouched, so automation never sees a lie about
	// actual risk), but are excluded from the printed OK/WARN/CRIT tally
	// so the summary reflects only what still needs a decision.
	AcceptedFindings []AcceptedFinding `yaml:"accepted_findings"`

	Thresholds ThresholdsConfig `yaml:"thresholds"`

	// Hosts configures `vpsguard fleet`'s remote targets. Empty means
	// fleet mode has nothing to do — see cmd/fleet.go.
	Hosts []HostConfig `yaml:"hosts"`
}

// HostConfig is one remote target for `vpsguard fleet`. Connecting relies
// entirely on the operator's own SSH setup (keys, agent, ~/.ssh/config) —
// vpsguard never handles credentials itself, same as how harden/checks
// shell out to real tools instead of reimplementing their logic.
type HostConfig struct {
	Name string `yaml:"name"`
	Addr string `yaml:"addr"`
	User string `yaml:"user"`
	// Port defaults to 22 when zero.
	Port int `yaml:"port"`
}

// AcceptedFinding matches findings by check name and a substring of their
// message — deliberately loose (not exact match) so small message wording
// changes between vpsguard versions don't silently un-acknowledge
// something an operator already reviewed.
type AcceptedFinding struct {
	Check           string `yaml:"check"`
	MessageContains string `yaml:"message_contains"`
}

// ThresholdsConfig holds per-check numeric threshold overrides. Only
// `kernel` has tunable thresholds today.
type ThresholdsConfig struct {
	Kernel KernelThresholds `yaml:"kernel"`
}

// KernelThresholds overrides internal/checks.SecurityUpdateWarnThreshold
// and SecurityUpdateCritThreshold. Zero means "use the built-in default"
// — there's no legitimate reason to set either to 0 pending updates as a
// threshold, so this is unambiguous.
type KernelThresholds struct {
	SecurityUpdateWarn int `yaml:"security_update_warn"`
	SecurityUpdateCrit int `yaml:"security_update_crit"`
}

// NotifyConfig configures where `vpsguard monitor` sends findings when it
// detects a change. Both WebhookURL and EmailTo may be set at once — every
// configured notifier is used. Neither being set means monitor stays
// stdout-only, same as before this existed.
type NotifyConfig struct {
	WebhookURL string `yaml:"webhook_url"`
	EmailTo    string `yaml:"email_to"`
	// MinSeverity is the lowest severity that triggers a notification:
	// "WARN" (default) or "CRIT". Findings below this are still printed to
	// stdout/--json as always, just not pushed out.
	MinSeverity string `yaml:"min_severity"`
}

// Load reads and parses the config file at path. A missing file is not an
// error — it returns a zero-value Config, since every setting is optional.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Config{}, nil
		}
		return Config{}, fmt.Errorf("reading %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cfg, nil
}
