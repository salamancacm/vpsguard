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
