package report

import (
	"fmt"
	"io"

	"github.com/fatih/color"
)

// PrintTable writes findings as a human-readable table with severity
// colors, followed by the summary line. This is the stable, scriptable
// format (also used for --json's sibling plain-table output) — anything
// cosmetic (live per-check progress) must build on PrintFindings and
// PrintSummary separately instead of changing this function's output.
func PrintTable(w io.Writer, findings []Finding) {
	PrintFindings(w, findings)
	fmt.Fprintln(w)
	PrintSummary(w, findings)
}

// PrintFindings writes just the per-finding lines, no summary.
func PrintFindings(w io.Writer, findings []Finding) {
	for _, f := range findings {
		badge := severityBadge(f.Severity)
		fmt.Fprintf(w, "%s  [%s] %s\n", badge, f.Check, f.Message)
		if f.Severity != OK && f.Remediation != "" {
			fmt.Fprintf(w, "        %s %s\n", color.HiBlackString("->"), f.Remediation)
		}
	}
}

// PrintSummary writes just the "N OK  N WARN  N CRIT" line.
func PrintSummary(w io.Writer, findings []Finding) {
	var okC, warnC, critC int
	for _, f := range findings {
		switch f.Severity {
		case OK:
			okC++
		case WARN:
			warnC++
		case CRIT:
			critC++
		}
	}
	fmt.Fprintf(w, "Summary: %s  %s  %s\n",
		color.GreenString("%d OK", okC),
		color.YellowString("%d WARN", warnC),
		color.RedString("%d CRIT", critC),
	)
}

// PrintCheckHeader announces which check is about to run. Interactive-mode
// only — callers must gate this behind Interactive().
func PrintCheckHeader(w io.Writer, name string) {
	fmt.Fprintln(w, color.New(color.FgCyan, color.Bold).Sprint("▸ ")+name)
}

func severityBadge(s Severity) string {
	switch s {
	case OK:
		return color.GreenString("[ OK ]")
	case WARN:
		return color.YellowString("[WARN]")
	case CRIT:
		return color.RedString("[CRIT]")
	default:
		return "[ ?? ]"
	}
}
