package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/salamancacm/vpsguard/internal/report"
)

func TestLoad_MissingFileIsNotAnError(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Load() on a missing file returned an error: %v", err)
	}
	if cfg.Notify.WebhookURL != "" || len(cfg.DisabledChecks) != 0 {
		t.Errorf("Load() on a missing file should return a zero-value Config, got %+v", cfg)
	}
}

func TestLoad_ParsesAllFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, `
notify:
  webhook_url: "https://example.com/hook"
  email_to: "ops@example.com"
  min_severity: "CRIT"
disabled_checks:
  - network
  - docker
accepted_findings:
  - check: network
    message_contains: "6379"
thresholds:
  kernel:
    security_update_warn: 5
    security_update_crit: 20
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load() error: %v", err)
	}

	if cfg.Notify.WebhookURL != "https://example.com/hook" {
		t.Errorf("Notify.WebhookURL = %q", cfg.Notify.WebhookURL)
	}
	if cfg.Notify.MinSeverity != "CRIT" {
		t.Errorf("Notify.MinSeverity = %q", cfg.Notify.MinSeverity)
	}
	if len(cfg.DisabledChecks) != 2 || cfg.DisabledChecks[0] != "network" {
		t.Errorf("DisabledChecks = %v", cfg.DisabledChecks)
	}
	if len(cfg.AcceptedFindings) != 1 || cfg.AcceptedFindings[0].Check != "network" {
		t.Errorf("AcceptedFindings = %v", cfg.AcceptedFindings)
	}
	if cfg.Thresholds.Kernel.SecurityUpdateWarn != 5 || cfg.Thresholds.Kernel.SecurityUpdateCrit != 20 {
		t.Errorf("Thresholds.Kernel = %+v", cfg.Thresholds.Kernel)
	}
}

func TestLoad_InvalidYAMLIsAnError(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	writeFile(t, path, "notify: [this is not a valid mapping structure :::")

	if _, err := Load(path); err == nil {
		t.Error("Load() on malformed YAML should return an error")
	}
}

func TestFilterDisabled(t *testing.T) {
	order := []string{"ssh", "firewall", "fail2ban", "users"}

	tests := []struct {
		name      string
		cfg       Config
		requested []string
		want      []string
	}{
		{
			name:      "no filter, nothing disabled: full default order",
			cfg:       Config{},
			requested: nil,
			want:      order,
		},
		{
			name:      "explicit --check filter is respected as-is when nothing disabled",
			cfg:       Config{},
			requested: []string{"ssh", "users"},
			want:      []string{"ssh", "users"},
		},
		{
			name:      "disabled checks removed from the default order",
			cfg:       Config{DisabledChecks: []string{"firewall"}},
			requested: nil,
			want:      []string{"ssh", "fail2ban", "users"},
		},
		{
			name:      "disabled checks removed from an explicit --check filter too",
			cfg:       Config{DisabledChecks: []string{"users"}},
			requested: []string{"ssh", "users", "fail2ban"},
			want:      []string{"ssh", "fail2ban"},
		},
		{
			name:      "everything disabled returns an empty list, not a fallback to all",
			cfg:       Config{DisabledChecks: order},
			requested: nil,
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.cfg.FilterDisabled(tt.requested, order)
			if len(got) != len(tt.want) {
				t.Fatalf("FilterDisabled() = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("FilterDisabled() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestMarkAccepted(t *testing.T) {
	cfg := Config{
		AcceptedFindings: []AcceptedFinding{
			{Check: "network", MessageContains: "6379 (redis)"},
		},
	}

	findings := []report.Finding{
		report.NewFinding("network", report.CRIT, "database port 6379 (redis) is listening on all interfaces (0.0.0.0)", "", false),
		report.NewFinding("network", report.CRIT, "database port 5432 (postgresql) is listening on all interfaces (0.0.0.0)", "", false),
	}

	got := cfg.MarkAccepted(findings)

	if !got[0].Acknowledged {
		t.Error("expected the redis finding to be marked Acknowledged")
	}
	if got[0].Severity != report.CRIT {
		t.Errorf("MarkAccepted must not change Severity, got %v", got[0].Severity)
	}
	if got[1].Acknowledged {
		t.Error("the unrelated postgresql finding should not be marked Acknowledged")
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing test fixture %s: %v", path, err)
	}
}
