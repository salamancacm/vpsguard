package snapshot

import (
	"strings"

	"github.com/salamancacm/vpsguard/internal/report"
)

// Diff compares old (previous run) against cur (just captured) and returns
// a Finding for every change worth a human's attention. An empty slice
// means nothing suspicious changed.
func Diff(old, cur Snapshot) []report.Finding {
	const check = "monitor"
	var findings []report.Finding

	for _, name := range setDiff(toSet(old.Users), toSet(cur.Users)) {
		findings = append(findings, report.NewFinding(check, report.WARN,
			"new user account detected: "+name, "verify you created it", false))
	}

	for _, name := range setDiff(toSet(old.UID0Users), toSet(cur.UID0Users)) {
		findings = append(findings, report.NewFinding(check, report.CRIT,
			"new UID 0 account detected: "+name,
			"this is a strong sign of compromise, investigate immediately", false))
	}

	for _, entry := range setDiff(toSet(old.SudoersEntries), toSet(cur.SudoersEntries)) {
		findings = append(findings, report.NewFinding(check, report.CRIT,
			"new entry in /etc/sudoers.d: "+entry,
			"review its contents immediately", false))
	}

	for user, curKeys := range cur.AuthorizedKeys {
		oldKeys := old.AuthorizedKeys[user]
		for _, key := range setDiff(toSet(oldKeys), toSet(curKeys)) {
			findings = append(findings, report.NewFinding(check, report.CRIT,
				"new SSH key authorized for '"+user+"': "+truncate(key, 60),
				"if you didn't add it, remove it from authorized_keys and rotate credentials", false))
		}
	}
	for user := range old.AuthorizedKeys {
		if _, stillExists := cur.AuthorizedKeys[user]; !stillExists {
			findings = append(findings, report.NewFinding(check, report.WARN,
				"user '"+user+"' no longer has authorized_keys (or the user was removed)", "", false))
		}
	}

	for _, port := range setDiff(toSet(old.ListeningPorts), toSet(cur.ListeningPorts)) {
		findings = append(findings, report.NewFinding(check, report.WARN,
			"new listening port: "+port, "verify it corresponds to an expected service", false))
	}

	for user, curEntries := range cur.CronEntries {
		oldEntries := old.CronEntries[user]
		for _, entry := range setDiff(toSet(oldEntries), toSet(curEntries)) {
			findings = append(findings, report.NewFinding(check, report.WARN,
				"new cron entry for '"+user+"': "+truncate(entry, 80),
				"", false))
		}
	}

	for _, name := range setDiff(toSet(old.RootProcesses), toSet(cur.RootProcesses)) {
		findings = append(findings, report.NewFinding(check, report.WARN,
			"new process running as root: "+name,
			"this can also be a normal package upgrade or service restart — verify it's expected", false))
	}

	for path, curHash := range cur.BinaryHashes {
		oldHash, existed := old.BinaryHashes[path]
		if existed && oldHash != curHash {
			findings = append(findings, report.NewFinding(check, report.CRIT,
				"critical binary changed: "+path,
				"this can also be a normal package update — verify with your package manager's log (e.g. 'apt changelog', 'dpkg -l') before assuming compromise", false))
		}
	}

	return findings
}

// DiffBaseline compares cur's watched-binary hashes against a pinned
// baseline (see `vpsguard baseline`), instead of the previous monitor run.
// Unlike Diff, this is scoped to watchedBinaries only: users/ports/
// processes naturally drift during normal operation, so diffing those
// against a fixed reference point (rather than the last run) would just be
// noise. Binaries are different — they should rarely legitimately change,
// and a baseline catches a swap that Diff alone would miss once it becomes
// the new "previous run" (e.g. re-compromised right after every monitor
// run, always looking unchanged one cycle later) or a swap that happened
// between two runs that were never compared to each other.
//
// vpsguard's own executable is deliberately excluded even though it's
// hashed into every snapshot's BinaryHashes — `vpsguard update` legitimately
// changes it, and a pinned baseline has no way to distinguish that from
// tampering.
func DiffBaseline(baseline, cur Snapshot) []report.Finding {
	const check = "monitor"
	var findings []report.Finding

	for _, path := range watchedBinaries {
		baseHash, inBaseline := baseline.BinaryHashes[path]
		if !inBaseline {
			continue
		}
		curHash, exists := cur.BinaryHashes[path]
		switch {
		case !exists:
			findings = append(findings, report.NewFinding(check, report.CRIT,
				"critical binary missing since baseline was set: "+path,
				"investigate immediately — this can also mean the package was legitimately removed", false))
		case curHash != baseHash:
			findings = append(findings, report.NewFinding(check, report.CRIT,
				"critical binary differs from baseline: "+path,
				"this can also be a normal package update — if expected, run 'vpsguard baseline' again to update the trusted reference", false))
		}
	}

	return findings
}

func toSet(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, i := range items {
		set[i] = true
	}
	return set
}

// setDiff returns entries present in b but not in a (i.e. what's new).
func setDiff(a, b map[string]bool) []string {
	var diff []string
	for k := range b {
		if !a[k] {
			diff = append(diff, k)
		}
	}
	return diff
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.TrimSpace(s[:max]) + "..."
}
