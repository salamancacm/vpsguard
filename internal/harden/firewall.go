package harden

import (
	"fmt"
	"strings"

	"github.com/salamancacm/vpsguard/internal/system"
)

// Firewall installs/enables ufw with a default-deny-incoming policy, always
// allowing the currently configured SSH port first so the operator doesn't
// get locked out.
func Firewall(dryRun bool) ([]string, error) {
	var applied []string

	if !system.CommandExists("ufw") {
		if dryRun {
			return []string{"[dry-run] would install ufw"}, nil
		}
		family := system.PackageFamily()
		var installErr error
		switch family {
		case "debian":
			_, installErr = system.Run("apt-get", "install", "-y", "ufw")
		case "rhel":
			_, installErr = system.Run("dnf", "install", "-y", "ufw")
		default:
			return nil, fmt.Errorf("unrecognized distro, install ufw manually")
		}
		if installErr != nil {
			return nil, fmt.Errorf("installing ufw: %w", installErr)
		}
		applied = append(applied, "ufw installed")
	}

	sshPort := currentSSHPort()
	if dryRun {
		applied = append(applied,
			fmt.Sprintf("[dry-run] would allow SSH port %s", sshPort),
			"[dry-run] would set 'ufw default deny incoming'",
			"[dry-run] would enable ufw",
		)
		return applied, nil
	}

	if _, err := system.Run("ufw", "allow", sshPort+"/tcp"); err != nil {
		return applied, fmt.Errorf("allowing SSH port %s in ufw: %w", sshPort, err)
	}
	applied = append(applied, "SSH port "+sshPort+"/tcp allowed in ufw")

	if _, err := system.Run("ufw", "default", "deny", "incoming"); err != nil {
		return applied, fmt.Errorf("setting ufw default policy: %w", err)
	}
	applied = append(applied, "ufw default policy: deny incoming")

	out, _ := system.Run("ufw", "status")
	if !strings.Contains(strings.ToLower(out), "status: active") {
		if _, err := system.Run("ufw", "--force", "enable"); err != nil {
			return applied, fmt.Errorf("enabling ufw: %w", err)
		}
		applied = append(applied, "ufw enabled")
	} else {
		applied = append(applied, "ufw was already active")
	}

	return applied, nil
}

// currentSSHPort reads the configured SSH port from sshd_config, defaulting
// to 22 if unset, so hardening the firewall never locks out the current
// SSH port.
func currentSSHPort() string {
	lines, ok := system.ReadFileLines(sshdConfigPath)
	if !ok {
		return "22"
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.EqualFold(fields[0], "Port") {
			return fields[1]
		}
	}
	return "22"
}
