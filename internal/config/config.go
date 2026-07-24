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
