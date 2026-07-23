package checks

import (
	"strings"

	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/system"
)

// Fail2ban checks whether fail2ban is installed, running, and has an sshd
// jail enabled.
func Fail2ban() []report.Finding {
	const check = "fail2ban"

	if !system.CommandExists("fail2ban-client") {
		return []report.Finding{
			report.NewFinding(check, report.CRIT,
				"fail2ban is not installed",
				"install it with 'apt install fail2ban' (or 'dnf install fail2ban') and enable the sshd jail", true),
		}
	}

	var findings []report.Finding

	out, err := system.Run("systemctl", "is-active", "fail2ban")
	if err == nil && strings.TrimSpace(out) == "active" {
		findings = append(findings, report.NewFinding(check, report.OK,
			"fail2ban is installed and active", "", false))
	} else {
		findings = append(findings, report.NewFinding(check, report.CRIT,
			"fail2ban is installed but the service is not active",
			"run 'systemctl enable --now fail2ban'", true))
		return findings
	}

	jails, jerr := system.Run("fail2ban-client", "status")
	if jerr == nil && strings.Contains(jails, "sshd") {
		findings = append(findings, report.NewFinding(check, report.OK,
			"the sshd jail is enabled in fail2ban", "", false))
	} else {
		findings = append(findings, report.NewFinding(check, report.WARN,
			"the sshd jail was not detected in fail2ban",
			"enable it in /etc/fail2ban/jail.local ([sshd] enabled = true) and restart fail2ban", true))
	}

	return findings
}
