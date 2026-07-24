package checks

import (
	"testing"

	"github.com/salamancacm/vpsguard/internal/report"
)

func TestCountDebianSecurityUpdates(t *testing.T) {
	// Real-shaped `apt list --upgradable` output.
	out := `Listing...
libssl3/jammy-security 3.0.2-0ubuntu1.10 amd64 [upgradable from: 3.0.2-0ubuntu1.9]
openssh-server/jammy-security 1:8.9p1-3ubuntu0.6 amd64 [upgradable from: 1:8.9p1-3ubuntu0.4]
vim/jammy 2:8.2.3995-1ubuntu2.15 amd64 [upgradable from: 2:8.2.3995-1ubuntu2.14]`

	if got := countDebianSecurityUpdates(out); got != 2 {
		t.Errorf("countDebianSecurityUpdates() = %d, want 2", got)
	}
}

func TestCountDebianSecurityUpdates_Empty(t *testing.T) {
	if got := countDebianSecurityUpdates("Listing...\n"); got != 0 {
		t.Errorf("countDebianSecurityUpdates() = %d, want 0", got)
	}
}

func TestCountRHELSecurityUpdates(t *testing.T) {
	out := `Last metadata expiration check: 0:12:34 ago on Mon 01 Jan 2026.
FEDORA-2026-abc123 Important/Sec. kernel-6.1.0-1.fc38.x86_64
FEDORA-2026-def456 Moderate/Sec.  openssl-3.0.9-1.fc38.x86_64

Updates Information Summary: available
`

	if got := countRHELSecurityUpdates(out); got != 2 {
		t.Errorf("countRHELSecurityUpdates() = %d, want 2", got)
	}
}

func TestSecurityUpdateFinding(t *testing.T) {
	origWarn, origCrit := SecurityUpdateWarnThreshold, SecurityUpdateCritThreshold
	SecurityUpdateWarnThreshold, SecurityUpdateCritThreshold = 1, 10
	defer func() {
		SecurityUpdateWarnThreshold, SecurityUpdateCritThreshold = origWarn, origCrit
	}()

	tests := []struct {
		count int
		want  report.Severity
	}{
		{0, report.OK},
		{1, report.WARN},
		{9, report.WARN},
		{10, report.CRIT},
		{50, report.CRIT},
	}

	for _, tt := range tests {
		got := securityUpdateFinding("kernel", tt.count)
		if got.Severity != tt.want {
			t.Errorf("securityUpdateFinding(%d).Severity = %v, want %v", tt.count, got.Severity, tt.want)
		}
	}
}

func TestSecurityUpdateFinding_RespectsConfiguredThresholds(t *testing.T) {
	origWarn, origCrit := SecurityUpdateWarnThreshold, SecurityUpdateCritThreshold
	defer func() {
		SecurityUpdateWarnThreshold, SecurityUpdateCritThreshold = origWarn, origCrit
	}()

	// Simulates internal/config.ThresholdsConfig raising the CRIT bar to 20,
	// as tested manually against a real host with 15 pending updates.
	SecurityUpdateWarnThreshold, SecurityUpdateCritThreshold = 1, 20

	got := securityUpdateFinding("kernel", 15)
	if got.Severity != report.WARN {
		t.Errorf("with crit threshold=20, securityUpdateFinding(15).Severity = %v, want WARN", got.Severity)
	}
}
