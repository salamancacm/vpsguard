package snapshot

import (
	"strings"
	"testing"

	"github.com/salamancacm/vpsguard/internal/report"
)

func TestDiff_NewSSHKeyIsCRIT(t *testing.T) {
	old := Snapshot{
		AuthorizedKeys: map[string][]string{
			"root": {"ssh-ed25519 AAAAlegit real@admin.com"},
		},
	}
	cur := Snapshot{
		AuthorizedKeys: map[string][]string{
			"root": {
				"ssh-ed25519 AAAAlegit real@admin.com",
				"ssh-ed25519 AAAAfake attacker@evil.com",
			},
		},
	}

	findings := Diff(old, cur)
	assertHasFinding(t, findings, report.CRIT, "new SSH key authorized for 'root'")
}

func TestDiff_NoChangesIsEmpty(t *testing.T) {
	snap := Snapshot{
		Users:          []string{"root:0", "deploy:1000"},
		ListeningPorts: []string{"22", "443"},
		AuthorizedKeys: map[string][]string{"root": {"ssh-ed25519 AAAA real@admin.com"}},
	}

	findings := Diff(snap, snap)
	if len(findings) != 0 {
		t.Errorf("Diff(x, x) = %+v, want no findings for identical snapshots", findings)
	}
}

func TestDiff_NewUID0AccountIsCRIT(t *testing.T) {
	old := Snapshot{UID0Users: nil}
	cur := Snapshot{UID0Users: []string{"backdoor"}}

	findings := Diff(old, cur)
	assertHasFinding(t, findings, report.CRIT, "new UID 0 account detected: backdoor")
}

func TestDiff_NewSudoersEntryIsCRIT(t *testing.T) {
	old := Snapshot{SudoersEntries: nil}
	cur := Snapshot{SudoersEntries: []string{"99-backdoor"}}

	findings := Diff(old, cur)
	assertHasFinding(t, findings, report.CRIT, "new entry in /etc/sudoers.d: 99-backdoor")
}

func TestDiff_NewUserAccountIsWARN(t *testing.T) {
	old := Snapshot{Users: []string{"root:0"}}
	cur := Snapshot{Users: []string{"root:0", "newuser:1001"}}

	findings := Diff(old, cur)
	assertHasFinding(t, findings, report.WARN, "new user account detected: newuser:1001")
}

func TestDiff_NewListeningPortIsWARN(t *testing.T) {
	old := Snapshot{ListeningPorts: []string{"22"}}
	cur := Snapshot{ListeningPorts: []string{"22", "31337"}}

	findings := Diff(old, cur)
	assertHasFinding(t, findings, report.WARN, "new listening port: 31337")
}

func TestDiff_NewRootProcessIsWARN(t *testing.T) {
	old := Snapshot{RootProcesses: []string{"sshd", "cron"}}
	cur := Snapshot{RootProcesses: []string{"sshd", "cron", "nc"}}

	findings := Diff(old, cur)
	assertHasFinding(t, findings, report.WARN, "new process running as root: nc")
}

func TestDiff_ChangedBinaryHashIsCRIT(t *testing.T) {
	old := Snapshot{BinaryHashes: map[string]string{"/bin/su": "aaaa"}}
	cur := Snapshot{BinaryHashes: map[string]string{"/bin/su": "bbbb"}}

	findings := Diff(old, cur)
	assertHasFinding(t, findings, report.CRIT, "critical binary changed: /bin/su")
}

func TestDiff_NewBinaryPathIsNotFlagged(t *testing.T) {
	// A path present in cur but absent from old (e.g. sshd just got
	// installed) isn't a "change" in the sense this check cares about —
	// only an existing, previously-hashed path changing value should CRIT.
	old := Snapshot{BinaryHashes: map[string]string{}}
	cur := Snapshot{BinaryHashes: map[string]string{"/usr/sbin/sshd": "aaaa"}}

	findings := Diff(old, cur)
	for _, f := range findings {
		if f.Check == "monitor" && f.Severity == report.CRIT {
			t.Errorf("Diff() flagged a newly-appeared binary path as changed: %+v", f)
		}
	}
}

func TestDiff_RemovedAuthorizedKeysIsWARN(t *testing.T) {
	old := Snapshot{AuthorizedKeys: map[string][]string{"deploy": {"ssh-ed25519 AAAA x@y.com"}}}
	cur := Snapshot{AuthorizedKeys: map[string][]string{}}

	findings := Diff(old, cur)
	assertHasFinding(t, findings, report.WARN, "user 'deploy' no longer has authorized_keys")
}

func assertHasFinding(t *testing.T, findings []report.Finding, sev report.Severity, messageContains string) {
	t.Helper()
	for _, f := range findings {
		if f.Severity == sev && strings.Contains(f.Message, messageContains) {
			return
		}
	}
	t.Errorf("expected a %v finding containing %q, got: %+v", sev, messageContains, findings)
}
