package report

import "math"

// Score computes a 0-100 compliance score from findings: each OK finding
// earns full credit, WARN half credit, CRIT none. Acknowledged findings are
// excluded, matching PrintSummary's counts -- an accepted finding shouldn't
// keep dragging the score down once a human has signed off on it.
//
// Half credit for WARN (rather than zero) reflects that vpsguard's own
// severities already separate "worth a second look" from "fix this now";
// collapsing both to zero credit would make the score indistinguishable
// from a host full of CRITs.
func Score(findings []Finding) int {
	var total, earned float64
	for _, f := range findings {
		if f.Acknowledged {
			continue
		}
		total++
		switch f.Severity {
		case OK:
			earned++
		case WARN:
			earned += 0.5
		}
	}
	if total == 0 {
		return 100
	}
	return int(math.Round(earned / total * 100))
}

// ScoreLabel returns a short qualitative label for a score, so the number
// reads at a glance without the reader needing to know the thresholds.
func ScoreLabel(score int) string {
	switch {
	case score >= 90:
		return "Good"
	case score >= 70:
		return "Needs attention"
	default:
		return "Critical"
	}
}
