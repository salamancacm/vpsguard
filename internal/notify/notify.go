// Package notify sends monitor findings somewhere a human will actually
// see them promptly, instead of only /var/log/vpsguard-monitor.log.
package notify

import "github.com/salamancacm/vpsguard/internal/report"

// Notifier pushes findings out to some external destination. Errors are
// meant to be logged, not fatal — a broken webhook must never make
// `vpsguard monitor` itself fail or stop writing to stdout/the log file.
type Notifier interface {
	Notify(findings []report.Finding) error
}

// severityRank orders severities for MinSeverity filtering.
func severityRank(s report.Severity) int {
	switch s {
	case report.CRIT:
		return 2
	case report.WARN:
		return 1
	default:
		return 0
	}
}

// Filter returns only findings at or above min (e.g. min=WARN keeps
// WARN and CRIT, drops OK).
func Filter(findings []report.Finding, min report.Severity) []report.Finding {
	var out []report.Finding
	for _, f := range findings {
		if severityRank(f.Severity) >= severityRank(min) {
			out = append(out, f)
		}
	}
	return out
}

// ParseMinSeverity maps a config string ("WARN"/"CRIT", case-insensitive)
// to a Severity, defaulting to WARN for empty or unrecognized values.
func ParseMinSeverity(s string) report.Severity {
	switch s {
	case "CRIT", "crit":
		return report.CRIT
	default:
		return report.WARN
	}
}
