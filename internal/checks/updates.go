package checks

import (
	"strings"

	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/system"
)

// Updates checks whether automatic security updates are configured, using
// the mechanism appropriate for the detected distro family.
func Updates() []report.Finding {
	const check = "updates"

	switch system.PackageFamily() {
	case "debian":
		return debianUpdateFindings(check)
	case "rhel":
		return rhelUpdateFindings(check)
	default:
		return []report.Finding{report.NewFinding(check, report.WARN,
			"unrecognized distro: could not determine the automatic update mechanism", "", false)}
	}
}

func debianUpdateFindings(check string) []report.Finding {
	confLines, ok := system.ReadFileLines("/etc/apt/apt.conf.d/20auto-upgrades")
	enabled := false
	if ok {
		for _, l := range confLines {
			if strings.Contains(l, `Unattended-Upgrade "1"`) {
				enabled = true
			}
		}
	}

	if enabled {
		return []report.Finding{report.NewFinding(check, report.OK,
			"unattended-upgrades is enabled", "", false)}
	}
	return []report.Finding{report.NewFinding(check, report.WARN,
		"unattended-upgrades is not enabled",
		"install and configure with 'apt install unattended-upgrades && dpkg-reconfigure -plow unattended-upgrades'", true)}
}

func rhelUpdateFindings(check string) []report.Finding {
	out, err := system.Run("systemctl", "is-active", "dnf-automatic.timer")
	if err == nil && strings.TrimSpace(out) == "active" {
		return []report.Finding{report.NewFinding(check, report.OK,
			"dnf-automatic.timer is active", "", false)}
	}
	return []report.Finding{report.NewFinding(check, report.WARN,
		"automatic updates are not active",
		"install and enable with 'dnf install dnf-automatic && systemctl enable --now dnf-automatic.timer'", true)}
}
