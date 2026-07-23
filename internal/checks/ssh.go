package checks

import (
	"strings"

	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/system"
)

const sshdConfigPath = "/etc/ssh/sshd_config"

// SSH audits sshd_config for the settings attackers rely on most: password
// auth, root login over SSH, and unlimited auth attempts.
func SSH() []report.Finding {
	const check = "ssh"

	lines, ok := system.ReadFileLines(sshdConfigPath)
	if !ok {
		return []report.Finding{
			report.NewFinding(check, report.WARN,
				"could not read "+sshdConfigPath, "", false),
		}
	}

	settings := parseSSHDConfig(lines)
	var findings []report.Finding

	permitRoot := settings["permitrootlogin"]
	switch permitRoot {
	case "no":
		findings = append(findings, report.NewFinding(check, report.OK,
			"PermitRootLogin is disabled", "", false))
	case "", "yes":
		findings = append(findings, report.NewFinding(check, report.CRIT,
			"PermitRootLogin allows root login over SSH",
			"set 'PermitRootLogin no' in "+sshdConfigPath, true))
	default:
		findings = append(findings, report.NewFinding(check, report.WARN,
			"PermitRootLogin='"+permitRoot+"' (verify this is intentional)",
			"use 'PermitRootLogin no' unless you specifically need '"+permitRoot+"'", true))
	}

	passwordAuth := settings["passwordauthentication"]
	switch passwordAuth {
	case "no":
		findings = append(findings, report.NewFinding(check, report.OK,
			"PasswordAuthentication is disabled (SSH keys only)", "", false))
	case "", "yes":
		findings = append(findings, report.NewFinding(check, report.CRIT,
			"PasswordAuthentication allows password login",
			"set 'PasswordAuthentication no' in "+sshdConfigPath+" (make sure you have an SSH key configured first)", true))
	default:
		findings = append(findings, report.NewFinding(check, report.WARN,
			"PasswordAuthentication has an unexpected value: '"+passwordAuth+"'", "", false))
	}

	port := settings["port"]
	if port == "" || port == "22" {
		findings = append(findings, report.NewFinding(check, report.WARN,
			"SSH is running on the default port (22)",
			"consider switching to a non-standard port to cut down on automated bot noise", false))
	} else {
		findings = append(findings, report.NewFinding(check, report.OK,
			"SSH is running on a non-standard port ("+port+")", "", false))
	}

	maxAuth := settings["maxauthtries"]
	if maxAuth == "" {
		findings = append(findings, report.NewFinding(check, report.WARN,
			"MaxAuthTries is not set (using sshd's default)",
			"set 'MaxAuthTries 3' in "+sshdConfigPath, true))
	}

	return findings
}

func parseSSHDConfig(lines []string) map[string]string {
	settings := make(map[string]string)
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		key := strings.ToLower(fields[0])
		// Keep the first occurrence: sshd_config uses first-match-wins.
		if _, exists := settings[key]; !exists {
			settings[key] = strings.ToLower(fields[1])
		}
	}
	return settings
}
