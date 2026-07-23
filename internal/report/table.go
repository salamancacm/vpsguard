package report

import (
	"fmt"
	"io"

	"github.com/fatih/color"
)

// PrintTable writes findings as a human-readable table with severity colors.
func PrintTable(w io.Writer, findings []Finding) {
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

	for _, f := range findings {
		badge := severityBadge(f.Severity)
		fmt.Fprintf(w, "%s  [%s] %s\n", badge, f.Check, f.Message)
		if f.Severity != OK && f.Remediation != "" {
			fmt.Fprintf(w, "        %s %s\n", color.HiBlackString("->"), f.Remediation)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Resumen: %s  %s  %s\n",
		color.GreenString("%d OK", okC),
		color.YellowString("%d WARN", warnC),
		color.RedString("%d CRIT", critC),
	)
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
