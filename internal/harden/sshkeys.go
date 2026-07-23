package harden

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/salamancacm/vpsguard/internal/system"
)

// SSHKeys fixes overly permissive ~/.ssh and authorized_keys permissions
// for every real user account (chmod 700 / 600 respectively).
func SSHKeys(dryRun bool) ([]string, error) {
	var applied []string

	for user, home := range system.RealUserHomes() {
		sshDir := filepath.Join(home, ".ssh")
		akPath := filepath.Join(sshDir, "authorized_keys")

		if info, err := os.Stat(sshDir); err == nil && info.Mode().Perm()&0o077 != 0 {
			if dryRun {
				applied = append(applied, fmt.Sprintf("[dry-run] chmod 700 %s (%s)", sshDir, user))
			} else if err := os.Chmod(sshDir, 0o700); err != nil {
				return applied, fmt.Errorf("chmod %s: %w", sshDir, err)
			} else {
				applied = append(applied, fmt.Sprintf("chmod 700 %s (%s)", sshDir, user))
			}
		}

		if info, err := os.Stat(akPath); err == nil && info.Mode().Perm()&0o077 != 0 {
			if dryRun {
				applied = append(applied, fmt.Sprintf("[dry-run] chmod 600 %s (%s)", akPath, user))
			} else if err := os.Chmod(akPath, 0o600); err != nil {
				return applied, fmt.Errorf("chmod %s: %w", akPath, err)
			} else {
				applied = append(applied, fmt.Sprintf("chmod 600 %s (%s)", akPath, user))
			}
		}
	}

	if len(applied) == 0 {
		applied = append(applied, ".ssh/authorized_keys permissions were already correct for all users")
	}
	return applied, nil
}
