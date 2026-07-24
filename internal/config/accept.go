package config

import (
	"strings"

	"github.com/salamancacm/vpsguard/internal/report"
)

// MarkAccepted sets Acknowledged=true on findings matching an
// AcceptedFindings rule. Severity and Message are left untouched — this
// only affects display/summary treatment, never what's actually reported.
func (c Config) MarkAccepted(findings []report.Finding) []report.Finding {
	if len(c.AcceptedFindings) == 0 {
		return findings
	}
	for i := range findings {
		for _, a := range c.AcceptedFindings {
			if findings[i].Check == a.Check && strings.Contains(findings[i].Message, a.MessageContains) {
				findings[i].Acknowledged = true
				break
			}
		}
	}
	return findings
}

// FilterDisabled removes disabled check names from a list, or returns all
// (defaultOrder) minus disabled if requested is empty (no explicit
// --check filter was given).
func (c Config) FilterDisabled(requested, defaultOrder []string) []string {
	names := requested
	if len(names) == 0 {
		names = defaultOrder
	}
	if len(c.DisabledChecks) == 0 {
		return names
	}

	disabled := make(map[string]bool, len(c.DisabledChecks))
	for _, d := range c.DisabledChecks {
		disabled[d] = true
	}

	var out []string
	for _, n := range names {
		if !disabled[n] {
			out = append(out, n)
		}
	}
	return out
}
