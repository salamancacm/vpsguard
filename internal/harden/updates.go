package harden

import (
	"fmt"
	"strings"

	"github.com/salamancacm/vpsguard/internal/system"
)

// Updates enables unattended/automatic security updates for the detected
// distro family. Idempotent: skips work if already enabled.
func Updates(dryRun bool) ([]string, error) {
	family := system.PackageFamily()

	switch family {
	case "debian":
		if debianAutoUpgradesEnabled() {
			return []string{"unattended-upgrades was already enabled"}, nil
		}
		if dryRun {
			return []string{"[dry-run] would install and configure unattended-upgrades"}, nil
		}
		if _, err := system.Run("apt-get", "install", "-y", "unattended-upgrades"); err != nil {
			return nil, fmt.Errorf("installing unattended-upgrades: %w", err)
		}
		if _, err := system.Run("dpkg-reconfigure", "-fnoninteractive", "-plow", "unattended-upgrades"); err != nil {
			return nil, fmt.Errorf("configuring unattended-upgrades: %w", err)
		}
		return []string{"unattended-upgrades installed and enabled"}, nil

	case "rhel":
		if dnfAutomaticActive() {
			return []string{"dnf-automatic.timer was already active"}, nil
		}
		if dryRun {
			return []string{"[dry-run] would install and enable dnf-automatic.timer"}, nil
		}
		if _, err := system.Run("dnf", "install", "-y", "dnf-automatic"); err != nil {
			return nil, fmt.Errorf("installing dnf-automatic: %w", err)
		}
		if _, err := system.Run("systemctl", "enable", "--now", "dnf-automatic.timer"); err != nil {
			return nil, fmt.Errorf("enabling dnf-automatic.timer: %w", err)
		}
		return []string{"dnf-automatic installed and enabled"}, nil

	default:
		return nil, fmt.Errorf("unrecognized distro, configure automatic updates manually")
	}
}

func debianAutoUpgradesEnabled() bool {
	lines, ok := system.ReadFileLines("/etc/apt/apt.conf.d/20auto-upgrades")
	if !ok {
		return false
	}
	for _, l := range lines {
		if strings.Contains(l, `Unattended-Upgrade "1"`) {
			return true
		}
	}
	return false
}

func dnfAutomaticActive() bool {
	out, err := system.Run("systemctl", "is-active", "dnf-automatic.timer")
	return err == nil && strings.TrimSpace(out) == "active"
}
