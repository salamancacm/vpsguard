package harden

import "fmt"

const sshdConfigPath = "/etc/ssh/sshd_config"

// SSH hardens sshd_config: disables root login and password auth, and sets
// a low MaxAuthTries. dryRun=true only describes what would change.
func SSH(dryRun bool) ([]string, error) {
	directives := [][2]string{
		{"PermitRootLogin", "no"},
		{"PasswordAuthentication", "no"},
		{"MaxAuthTries", "3"},
	}

	var applied []string
	if dryRun {
		for _, d := range directives {
			applied = append(applied, fmt.Sprintf("[dry-run] would set '%s %s' in %s", d[0], d[1], sshdConfigPath))
		}
		return applied, nil
	}

	backupPath, err := BackupFile(sshdConfigPath)
	if err != nil {
		return nil, fmt.Errorf("backing up %s: %w", sshdConfigPath, err)
	}
	if backupPath != "" {
		applied = append(applied, "backup saved to "+backupPath)
	}

	changedAny := false
	for _, d := range directives {
		changed, err := SetDirective(sshdConfigPath, d[0], d[1])
		if err != nil {
			return applied, fmt.Errorf("writing %s to %s: %w", d[0], sshdConfigPath, err)
		}
		if changed {
			changedAny = true
			applied = append(applied, fmt.Sprintf("'%s %s' applied to %s", d[0], d[1], sshdConfigPath))
		}
	}

	if !changedAny {
		applied = append(applied, "sshd_config was already correctly configured")
	} else {
		applied = append(applied, "remember to run 'systemctl reload sshd' to apply the changes (and verify your SSH key works before closing the current session)")
	}
	return applied, nil
}
