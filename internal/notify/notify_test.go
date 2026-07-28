package notify

import (
	"testing"

	"github.com/salamancacm/vpsguard/internal/report"
)

func TestParseMinSeverity(t *testing.T) {
	tests := map[string]report.Severity{
		"CRIT":  report.CRIT,
		"crit":  report.CRIT,
		"WARN":  report.WARN,
		"warn":  report.WARN,
		"":      report.WARN, // default
		"bogus": report.WARN, // unrecognized falls back to the safe default
	}
	for in, want := range tests {
		if got := ParseMinSeverity(in); got != want {
			t.Errorf("ParseMinSeverity(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestFilter(t *testing.T) {
	findings := []report.Finding{
		report.NewFinding("ssh", report.OK, "fine", "", false),
		report.NewFinding("ssh", report.WARN, "hmm", "", false),
		report.NewFinding("ssh", report.CRIT, "bad", "", false),
	}

	warnAndUp := Filter(findings, report.WARN)
	if len(warnAndUp) != 2 {
		t.Errorf("Filter(min=WARN) returned %d findings, want 2 (WARN+CRIT)", len(warnAndUp))
	}

	critOnly := Filter(findings, report.CRIT)
	if len(critOnly) != 1 || critOnly[0].Severity != report.CRIT {
		t.Errorf("Filter(min=CRIT) = %+v, want only the CRIT finding", critOnly)
	}
}

func TestFilter_EmptyInput(t *testing.T) {
	if got := Filter(nil, report.WARN); len(got) != 0 {
		t.Errorf("Filter(nil) = %v, want empty", got)
	}
}

func TestMaxSeverity(t *testing.T) {
	tests := []struct {
		name     string
		findings []report.Finding
		want     report.Severity
	}{
		{"empty", nil, report.OK},
		{"all OK", []report.Finding{report.NewFinding("ssh", report.OK, "", "", false)}, report.OK},
		{
			name: "WARN and CRIT mixed, CRIT wins",
			findings: []report.Finding{
				report.NewFinding("ssh", report.WARN, "", "", false),
				report.NewFinding("firewall", report.CRIT, "", "", false),
			},
			want: report.CRIT,
		},
		{
			name: "order doesn't matter",
			findings: []report.Finding{
				report.NewFinding("firewall", report.CRIT, "", "", false),
				report.NewFinding("ssh", report.WARN, "", "", false),
			},
			want: report.CRIT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := maxSeverity(tt.findings); got != tt.want {
				t.Errorf("maxSeverity(%v) = %v, want %v", tt.findings, got, tt.want)
			}
		})
	}
}

func TestFindingsList(t *testing.T) {
	findings := []report.Finding{
		report.NewFinding("ssh", report.CRIT, "root login enabled", "", false),
	}
	got := findingsList(findings)
	want := "[CRIT] [ssh] root login enabled\n"
	if got != want {
		t.Errorf("findingsList(%v) = %q, want %q", findings, got, want)
	}
}
