package checks

import (
	"strconv"
	"strings"

	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/system"
)

// systemCronDirs are the standard system-level cron locations distros ship.
var systemCronDirs = []string{
	"/etc/cron.d",
	"/etc/cron.hourly",
	"/etc/cron.daily",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
}

// Cron lists user crontabs and system cron directories. It cannot reliably
// tell "malicious" from "legitimate" without a baseline (that's what
// `vpsguard monitor` is for), so everything found is reported as informational
// WARN for the human to eyeball, and a clean state is OK.
func Cron() []report.Finding {
	const check = "cron"
	var findings []report.Finding

	for user, home := range system.RealUserHomes() {
		out, err := system.Run("crontab", "-l", "-u", user)
		if err != nil {
			continue // no crontab for this user
		}
		var entries []string
		for _, line := range strings.Split(out, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			entries = append(entries, line)
		}
		if len(entries) > 0 {
			findings = append(findings, report.NewFinding(check, report.WARN,
				user+" ("+home+") has "+strconv.Itoa(len(entries))+" crontab entrie(s): verify they're legitimate",
				"", false))
		}
	}

	for _, dir := range systemCronDirs {
		entries, err := system.ListDir(dir)
		if err != nil || len(entries) == 0 {
			continue
		}
		findings = append(findings, report.NewFinding(check, report.WARN,
			dir+" contains: "+strings.Join(entries, ", "),
			"", false))
	}

	if len(findings) == 0 {
		findings = append(findings, report.NewFinding(check, report.OK,
			"no user crontabs or custom /etc/cron.* entries found", "", false))
	}

	return findings
}
