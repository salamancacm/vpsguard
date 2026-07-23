package harden

import (
	"fmt"
	"os"
	"strings"

	"github.com/salamancacm/vpsguard/internal/system"
)

const jailLocalPath = "/etc/fail2ban/jail.local"

// Fail2ban installs fail2ban if missing, writes a minimal jail.local
// enabling the sshd jail, and (re)starts the service.
func Fail2ban(dryRun bool) ([]string, error) {
	var applied []string

	if !system.CommandExists("fail2ban-client") {
		if dryRun {
			return []string{"[dry-run] would install fail2ban"}, nil
		}
		family := system.PackageFamily()
		var installErr error
		switch family {
		case "debian":
			_, installErr = system.Run("apt-get", "install", "-y", "fail2ban")
		case "rhel":
			_, installErr = system.Run("dnf", "install", "-y", "fail2ban")
		default:
			return nil, fmt.Errorf("unrecognized distro, install fail2ban manually")
		}
		if installErr != nil {
			return nil, fmt.Errorf("installing fail2ban: %w", installErr)
		}
		applied = append(applied, "fail2ban installed")
	}

	sshdJailBlock := "[sshd]\nenabled = true\n"

	existing, hadFile := system.ReadFileLines(jailLocalPath)
	needsWrite := !hadFile || !strings.Contains(strings.Join(existing, "\n"), "[sshd]")

	if dryRun {
		if needsWrite {
			applied = append(applied, "[dry-run] would enable the [sshd] jail in "+jailLocalPath)
		}
		applied = append(applied, "[dry-run] would ensure the fail2ban service is active")
		return applied, nil
	}

	if needsWrite {
		if hadFile {
			backupPath, err := BackupFile(jailLocalPath)
			if err != nil {
				return applied, fmt.Errorf("backing up %s: %w", jailLocalPath, err)
			}
			if backupPath != "" {
				applied = append(applied, "backup saved to "+backupPath)
			}
		}
		f, err := os.OpenFile(jailLocalPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return applied, fmt.Errorf("writing %s: %w", jailLocalPath, err)
		}
		if _, err := f.WriteString("\n" + sshdJailBlock); err != nil {
			f.Close()
			return applied, fmt.Errorf("writing %s: %w", jailLocalPath, err)
		}
		f.Close()
		applied = append(applied, "[sshd] jail enabled in "+jailLocalPath)
	}

	if _, err := system.Run("systemctl", "enable", "--now", "fail2ban"); err != nil {
		return applied, fmt.Errorf("enabling the fail2ban service: %w", err)
	}
	if needsWrite {
		if _, err := system.Run("systemctl", "restart", "fail2ban"); err != nil {
			return applied, fmt.Errorf("restarting fail2ban: %w", err)
		}
		applied = append(applied, "fail2ban restarted to apply the jail")
	} else {
		applied = append(applied, "fail2ban was already active with the sshd jail enabled")
	}

	return applied, nil
}
