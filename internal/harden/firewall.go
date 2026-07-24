package harden

import (
	"fmt"
	"strings"

	"github.com/salamancacm/vpsguard/internal/system"
)

// Firewall installs/enables a default-deny-incoming firewall, always
// allowing the currently configured SSH port first so the operator
// doesn't get locked out. The mechanism is distro-idiomatic: ufw on
// Debian/Ubuntu, firewalld on RHEL family — installing 'ufw' via dnf
// fails outright (it isn't in RHEL/Rocky's default repos, ufw is a
// Debian-ecosystem tool), so this must branch by family rather than
// assuming one tool everywhere.
func Firewall(dryRun bool) ([]string, error) {
	switch system.PackageFamily() {
	case "debian":
		return ufwFirewall(dryRun)
	case "rhel":
		return firewalldFirewall(dryRun)
	default:
		return nil, fmt.Errorf("unrecognized distro, configure a firewall manually")
	}
}

func ufwFirewall(dryRun bool) ([]string, error) {
	var applied []string

	if !system.CommandExists("ufw") {
		if dryRun {
			return []string{"[dry-run] would install ufw"}, nil
		}
		if _, err := system.Run("apt-get", "install", "-y", "ufw"); err != nil {
			return nil, fmt.Errorf("installing ufw: %w", err)
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

// firewalldFirewall installs firewalld (RHEL family's default firewall
// manager, already present on most real RHEL/Rocky/Alma VPS images out of
// the box) and permanently allows the SSH port.
//
// The port is added via 'firewall-offline-cmd', not 'firewall-cmd',
// deliberately: firewall-cmd talks to the live firewalld daemon over
// D-Bus and fails if it isn't running yet (e.g. right after a fresh
// install, or in a container without systemd/D-Bus), while
// firewall-offline-cmd edits the persistent zone config directly and
// works either way — the change then takes effect once the service
// starts. firewalld's default zone already denies unlisted inbound
// traffic out of the box, so unlike ufw there's no separate
// "default deny incoming" step needed.
func firewalldFirewall(dryRun bool) ([]string, error) {
	var applied []string

	if !system.CommandExists("firewall-cmd") {
		if dryRun {
			return []string{"[dry-run] would install firewalld"}, nil
		}
		if _, err := system.Run("dnf", "install", "-y", "firewalld"); err != nil {
			return nil, fmt.Errorf("installing firewalld: %w", err)
		}
		applied = append(applied, "firewalld installed")
	}

	sshPort := currentSSHPort()
	if dryRun {
		applied = append(applied,
			fmt.Sprintf("[dry-run] would permanently allow SSH port %s in firewalld", sshPort),
			"[dry-run] would enable firewalld",
		)
		return applied, nil
	}

	if _, err := system.Run("firewall-offline-cmd", "--add-port="+sshPort+"/tcp"); err != nil {
		return applied, fmt.Errorf("allowing SSH port %s in firewalld: %w", sshPort, err)
	}
	applied = append(applied, "SSH port "+sshPort+"/tcp allowed in firewalld's default zone")

	if _, err := system.Run("systemctl", "enable", "--now", "firewalld"); err != nil {
		return applied, fmt.Errorf("enabling firewalld: %w", err)
	}
	applied = append(applied, "firewalld enabled")

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
