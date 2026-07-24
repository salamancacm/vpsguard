package checks

import (
	"strings"

	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/system"
)

// Firewall checks whether a firewall is installed, active, and defaulting
// to deny. Supports ufw, firewalld, and raw nftables/iptables — checked
// in that order, since a system can have more than one installed and
// ufw/firewalld (the higher-level, distro-idiomatic managers) are what
// actually matters if present.
func Firewall() []report.Finding {
	const check = "firewall"

	if system.CommandExists("ufw") {
		return ufwFindings(check)
	}
	if system.CommandExists("firewall-cmd") {
		return firewalldFindings(check)
	}
	if system.CommandExists("nft") {
		return nftFindings(check)
	}
	if system.CommandExists("iptables") {
		return iptablesFindings(check)
	}

	return []report.Finding{
		report.NewFinding(check, report.CRIT,
			"no firewall found (ufw/firewalld/nftables/iptables)",
			"install and enable one — 'apt install ufw && ufw enable' (Debian/Ubuntu) or 'dnf install firewalld && systemctl enable --now firewalld' (RHEL family)", true),
	}
}

func ufwFindings(check string) []report.Finding {
	out, _ := system.Run("ufw", "status", "verbose")
	lower := strings.ToLower(out)

	var findings []report.Finding
	if strings.Contains(lower, "status: active") {
		findings = append(findings, report.NewFinding(check, report.OK,
			"ufw is active", "", false))
	} else {
		findings = append(findings, report.NewFinding(check, report.CRIT,
			"ufw is installed but inactive",
			"enable it with 'ufw enable' (make sure the SSH port is allowed first)", true))
		return findings
	}

	if strings.Contains(lower, "default: deny (incoming)") {
		findings = append(findings, report.NewFinding(check, report.OK,
			"ufw's default policy is to deny incoming traffic", "", false))
	} else {
		findings = append(findings, report.NewFinding(check, report.WARN,
			"ufw's default policy is not 'deny incoming'",
			"run 'ufw default deny incoming'", true))
	}

	return findings
}

func firewalldFindings(check string) []report.Finding {
	out, err := system.Run("firewall-cmd", "--state")
	if err == nil && strings.TrimSpace(out) == "running" {
		return []report.Finding{report.NewFinding(check, report.OK,
			"firewalld is active", "", false)}
	}
	return []report.Finding{report.NewFinding(check, report.CRIT,
		"firewalld is installed but not running",
		"enable it with 'systemctl enable --now firewalld'", true)}
}

func nftFindings(check string) []report.Finding {
	out, err := system.Run("systemctl", "is-active", "nftables")
	active := err == nil && strings.TrimSpace(out) == "active"

	if active {
		return []report.Finding{report.NewFinding(check, report.OK,
			"nftables is active", "", false)}
	}
	return []report.Finding{report.NewFinding(check, report.WARN,
		"nftables is installed but the service is not active",
		"check 'systemctl enable --now nftables' and your rules in /etc/nftables.conf", false)}
}

func iptablesFindings(check string) []report.Finding {
	out, _ := system.Run("iptables", "-L", "INPUT")
	if strings.Contains(out, "policy DROP") || strings.Contains(out, "policy REJECT") {
		return []report.Finding{report.NewFinding(check, report.OK,
			"iptables INPUT policy is DROP/REJECT", "", false)}
	}
	return []report.Finding{report.NewFinding(check, report.WARN,
		"iptables is present but the INPUT policy is ACCEPT (allows everything by default)",
		"consider switching to ufw or defining explicit rules with a DROP policy", false)}
}
