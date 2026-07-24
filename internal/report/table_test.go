package report

import (
	"bytes"
	"strings"
	"testing"
)

func TestPrintSummary_Counts(t *testing.T) {
	findings := []Finding{
		NewFinding("ssh", OK, "fine", "", false),
		NewFinding("ssh", OK, "also fine", "", false),
		NewFinding("firewall", WARN, "meh", "", false),
		NewFinding("fail2ban", CRIT, "bad", "", false),
	}

	var buf bytes.Buffer
	PrintSummary(&buf, findings)
	out := buf.String()

	for _, want := range []string{"2 OK", "1 WARN", "1 CRIT"} {
		if !strings.Contains(out, want) {
			t.Errorf("PrintSummary() output %q missing %q", out, want)
		}
	}
}

func TestPrintSummary_ExcludesAcknowledged(t *testing.T) {
	findings := []Finding{
		NewFinding("ssh", CRIT, "should be excluded", "", false),
		NewFinding("ssh", WARN, "should be counted", "", false),
	}
	findings[0].Acknowledged = true

	var buf bytes.Buffer
	PrintSummary(&buf, findings)
	out := buf.String()

	if !strings.Contains(out, "0 CRIT") {
		t.Errorf("acknowledged CRIT finding was still counted in summary: %q", out)
	}
	if !strings.Contains(out, "1 WARN") {
		t.Errorf("non-acknowledged WARN finding wasn't counted: %q", out)
	}
}

func TestPrintFindings_AcknowledgedGetsACKTag(t *testing.T) {
	f := NewFinding("ssh", CRIT, "an accepted finding", "", false)
	f.Acknowledged = true

	var buf bytes.Buffer
	PrintFindings(&buf, []Finding{f})
	out := buf.String()

	if !strings.Contains(out, "[ACK]") {
		t.Errorf("PrintFindings() output for an acknowledged finding missing [ACK] tag: %q", out)
	}
	if !strings.Contains(out, "an accepted finding") {
		t.Errorf("PrintFindings() should still print the original message: %q", out)
	}
}

func TestPrintFindings_BetaGetsBETATag(t *testing.T) {
	f := NewBetaFinding("cloud", CRIT, "a beta finding", "", false)

	var buf bytes.Buffer
	PrintFindings(&buf, []Finding{f})
	out := buf.String()

	if !strings.Contains(out, "[BETA]") {
		t.Errorf("PrintFindings() output for a beta finding missing [BETA] tag: %q", out)
	}
}

func TestPrintFindings_NonAcknowledgedHasNoTag(t *testing.T) {
	f := NewFinding("ssh", CRIT, "a normal finding", "", false)

	var buf bytes.Buffer
	PrintFindings(&buf, []Finding{f})
	out := buf.String()

	if strings.Contains(out, "[ACK]") {
		t.Errorf("PrintFindings() should not tag non-acknowledged findings: %q", out)
	}
}

func TestPrintFindings_OKFindingsSkipRemediationLine(t *testing.T) {
	f := NewFinding("ssh", OK, "all good", "this should never print", false)

	var buf bytes.Buffer
	PrintFindings(&buf, []Finding{f})
	out := buf.String()

	if strings.Contains(out, "this should never print") {
		t.Errorf("PrintFindings() printed a remediation for an OK finding: %q", out)
	}
}
