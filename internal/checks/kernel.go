package checks

import (
	"strconv"
	"strings"

	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/system"
)

// securityUpdateWarnThreshold and securityUpdateCritThreshold bound how
// many pending security updates escalate this from a nudge to urgent.
const (
	securityUpdateWarnThreshold = 1
	securityUpdateCritThreshold = 10
)

// Kernel checks whether the running kernel is stale (a newer one is
// installed but not yet active, requiring a reboot) and how many
// security-relevant package updates are pending. Unlike `updates`, which
// only checks that *automatic* updates are configured, this reflects
// whether the system is actually up to date right now.
func Kernel() []report.Finding {
	const check = "kernel"
	var findings []report.Finding

	findings = append(findings, rebootRequiredFinding(check))

	switch system.PackageFamily() {
	case "debian":
		findings = append(findings, debianSecurityUpdateFinding(check))
	case "rhel":
		findings = append(findings, rhelSecurityUpdateFinding(check))
	default:
		findings = append(findings, report.NewFinding(check, report.WARN,
			"unrecognized distro: could not check for pending security updates", "", false))
	}

	return findings
}

// rebootRequiredFinding checks Debian/Ubuntu's reboot-required marker file.
// RHEL-family distros don't have a universal equivalent (needrestart /
// dnf-utils' needs-restarting are optional add-ons), so this stays
// Debian-specific for now rather than guessing.
func rebootRequiredFinding(check string) report.Finding {
	if _, ok := system.ReadFileLines("/var/run/reboot-required"); ok {
		return report.NewFinding(check, report.WARN,
			"a newer kernel (or other component requiring a restart) is installed but not yet active",
			"reboot during a maintenance window to apply it", false)
	}
	return report.NewFinding(check, report.OK,
		"no pending reboot required", "", false)
}

func debianSecurityUpdateFinding(check string) report.Finding {
	out, err := system.Run("apt", "list", "--upgradable")
	if err != nil {
		return report.NewFinding(check, report.WARN,
			"could not check for pending security updates ('apt list --upgradable' failed)", "", false)
	}

	count := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "-security") {
			count++
		}
	}

	return securityUpdateFinding(check, count)
}

func rhelSecurityUpdateFinding(check string) report.Finding {
	if !system.CommandExists("dnf") {
		return report.NewFinding(check, report.WARN,
			"could not check for pending security updates (dnf not found)", "", false)
	}

	out, err := system.Run("dnf", "updateinfo", "list", "security")
	if err != nil {
		return report.NewFinding(check, report.WARN,
			"could not check for pending security updates ('dnf updateinfo list security' failed)", "", false)
	}

	count := 0
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "Last metadata") || strings.HasPrefix(line, "Updates Information Summary") {
			continue
		}
		count++
	}

	return securityUpdateFinding(check, count)
}

func securityUpdateFinding(check string, count int) report.Finding {
	countStr := strconv.Itoa(count) + " pending security update(s)"
	switch {
	case count >= securityUpdateCritThreshold:
		return report.NewFinding(check, report.CRIT,
			countStr, "apply them soon: 'apt upgrade' (or the dnf/yum equivalent)", false)
	case count >= securityUpdateWarnThreshold:
		return report.NewFinding(check, report.WARN,
			countStr, "apply them: 'apt upgrade' (or the dnf/yum equivalent)", false)
	default:
		return report.NewFinding(check, report.OK,
			"no pending security updates", "", false)
	}
}
