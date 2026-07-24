package checks

import (
	"strconv"
	"strings"

	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/system"
)

// Users audits /etc/passwd, /etc/shadow and sudoers.d for accounts that
// shouldn't exist: extra UID 0 users, accounts with an empty password, and
// custom sudoers entries worth a human's attention.
func Users() []report.Finding {
	const check = "users"
	var findings []report.Finding

	findings = append(findings, checkUID0Accounts(check)...)
	findings = append(findings, checkEmptyPasswords(check)...)
	findings = append(findings, checkSudoersD(check)...)

	return findings
}

func checkUID0Accounts(check string) []report.Finding {
	lines, ok := system.ReadFileLines("/etc/passwd")
	if !ok {
		return []report.Finding{report.NewFinding(check, report.WARN,
			"could not read /etc/passwd", "", false)}
	}

	extraRoot := uid0AccountsBesidesRoot(lines)

	if len(extraRoot) == 0 {
		return []report.Finding{report.NewFinding(check, report.OK,
			"only 'root' has UID 0", "", false)}
	}
	return []report.Finding{report.NewFinding(check, report.CRIT,
		"accounts with UID 0 besides root: "+strings.Join(extraRoot, ", "),
		"remove or fix the UID of these accounts: only root should have UID 0", false)}
}

func checkEmptyPasswords(check string) []report.Finding {
	lines, ok := system.ReadFileLines("/etc/shadow")
	if !ok {
		// Not readable as non-root, or doesn't exist. Not fatal; just skip.
		return []report.Finding{report.NewFinding(check, report.WARN,
			"could not read /etc/shadow (did you run vpsguard without sudo/root?)", "", false)}
	}

	empty := emptyPasswordAccounts(lines)

	if len(empty) == 0 {
		return []report.Finding{report.NewFinding(check, report.OK,
			"no account has an empty password", "", false)}
	}
	return []report.Finding{report.NewFinding(check, report.CRIT,
		"accounts with an empty password: "+strings.Join(empty, ", "),
		"lock these accounts with 'passwd -l <user>' or assign them a password", false)}
}

// uid0AccountsBesidesRoot returns /etc/passwd account names with UID 0
// other than "root" itself.
func uid0AccountsBesidesRoot(passwdLines []string) []string {
	var extraRoot []string
	for _, line := range passwdLines {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil {
			continue
		}
		if uid == 0 && fields[0] != "root" {
			extraRoot = append(extraRoot, fields[0])
		}
	}
	return extraRoot
}

// emptyPasswordAccounts returns /etc/shadow account names whose password
// field is empty.
func emptyPasswordAccounts(shadowLines []string) []string {
	var empty []string
	for _, line := range shadowLines {
		fields := strings.Split(line, ":")
		if len(fields) < 2 {
			continue
		}
		if fields[1] == "" {
			empty = append(empty, fields[0])
		}
	}
	return empty
}

func checkSudoersD(check string) []report.Finding {
	entries, err := system.ListDir("/etc/sudoers.d")
	if err != nil || len(entries) == 0 {
		return []report.Finding{report.NewFinding(check, report.OK,
			"no custom entries in /etc/sudoers.d", "", false)}
	}
	return []report.Finding{report.NewFinding(check, report.WARN,
		"/etc/sudoers.d has entries: "+strings.Join(entries, ", ")+" (verify they're legitimate)",
		"", false)}
}
