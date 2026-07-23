package checks

import (
	"os"
	"path/filepath"
	"strconv"

	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/system"
)

// SSHKeys inspects each real user's ~/.ssh/authorized_keys: how many keys
// are trusted, and whether file/dir permissions are loose enough for other
// users to tamper with them.
func SSHKeys() []report.Finding {
	const check = "sshkeys"
	var findings []report.Finding

	homes := system.RealUserHomes()
	if len(homes) == 0 {
		return []report.Finding{report.NewFinding(check, report.WARN,
			"no user accounts with a home directory were found", "", false)}
	}

	for user, home := range homes {
		sshDir := filepath.Join(home, ".ssh")
		akPath := filepath.Join(sshDir, "authorized_keys")

		if info, err := os.Stat(sshDir); err == nil {
			if info.Mode().Perm()&0o077 != 0 {
				findings = append(findings, report.NewFinding(check, report.WARN,
					user+": "+sshDir+" has overly permissive permissions ("+info.Mode().Perm().String()+")",
					"run 'chmod 700 "+sshDir+"'", true))
			}
		}

		lines, ok := system.ReadFileLines(akPath)
		if !ok {
			continue // user has no authorized_keys, nothing to check
		}

		if info, err := os.Stat(akPath); err == nil && info.Mode().Perm()&0o077 != 0 {
			findings = append(findings, report.NewFinding(check, report.WARN,
				user+": "+akPath+" has overly permissive permissions ("+info.Mode().Perm().String()+")",
				"run 'chmod 600 "+akPath+"'", true))
		}

		findings = append(findings, report.NewFinding(check, report.OK,
			user+": "+strconv.Itoa(len(lines))+" authorized SSH key(s) in "+akPath, "", false))
	}

	return findings
}
