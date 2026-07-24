package checks

import (
	"os"
	"strings"

	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/system"
)

const dockerSocketPath = "/var/run/docker.sock"

// Docker checks for a Docker installation exposed in an unsafe way: the
// daemon reachable over unauthenticated TCP, or the local socket left with
// looser-than-default permissions. Either is roughly equivalent to root on
// the host for anyone who can reach it.
func Docker() []report.Finding {
	const check = "docker"

	sockInfo, sockErr := os.Stat(dockerSocketPath)
	installed := system.CommandExists("docker") || sockErr == nil
	if !installed {
		return []report.Finding{report.NewFinding(check, report.OK,
			"Docker is not installed", "", false)}
	}

	var findings []report.Finding

	if sockErr == nil {
		findings = append(findings, socketPermissionFinding(check, sockInfo.Mode().Perm()))
	}

	if listeningOnInsecureTCP() {
		findings = append(findings, report.NewFinding(check, report.CRIT,
			"the Docker daemon appears to be listening on an unauthenticated TCP port (2375)",
			"disable the TCP listener or require TLS client certs (dockerd --tlsverify); anyone who can reach this port has root-equivalent access to the host", false))
	}

	if len(findings) == 0 {
		findings = append(findings, report.NewFinding(check, report.OK,
			"Docker is installed with a standard, socket-only configuration", "", false))
	}

	return findings
}

func socketPermissionFinding(check string, perm os.FileMode) report.Finding {
	switch {
	case perm&0o002 != 0:
		return report.NewFinding(check, report.CRIT,
			dockerSocketPath+" is world-writable ("+perm.String()+")",
			"run 'chmod 660 "+dockerSocketPath+"' — anyone on the system can currently gain root via this socket", false)
	case perm&0o077 != 0o060 && perm&0o077 != 0:
		return report.NewFinding(check, report.WARN,
			dockerSocketPath+" has looser-than-default permissions ("+perm.String()+")",
			"the standard permissions are 0660 (root:docker) — verify this is intentional", false)
	default:
		return report.NewFinding(check, report.OK,
			dockerSocketPath+" permissions look standard ("+perm.String()+")", "", false)
	}
}

// listeningOnInsecureTCP reports whether something is listening on port
// 2375, Docker's conventional unencrypted, unauthenticated TCP port.
//
// Uses `ss -tulnp` (not `-tln`) to match the column layout parsed
// elsewhere in this package (see network.go): the "-u" flag adds a Netid
// column, which is what puts "Local Address:Port" at fields[4].
func listeningOnInsecureTCP() bool {
	if !system.CommandExists("ss") {
		return false
	}
	out, err := system.Run("ss", "-tulnp")
	if err != nil {
		return false
	}
	return hasInsecureTCPListener(out)
}

// hasInsecureTCPListener checks `ss -tulnp`-formatted output for anything
// listening on port 2375.
func hasInsecureTCPListener(ssOutput string) bool {
	for _, line := range strings.Split(ssOutput, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		addr := fields[4]
		if strings.HasSuffix(addr, ":2375") {
			return true
		}
	}
	return false
}
