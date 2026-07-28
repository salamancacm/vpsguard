package checks

import (
	"encoding/json"
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

	findings = append(findings, containerFindings(check)...)
	findings = append(findings, dockerGroupFindings(check)...)

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

// dockerInspectResult is the subset of `docker inspect` output this check
// cares about, for one container.
type dockerInspectResult struct {
	Name   string `json:"Name"`
	Config struct {
		User string `json:"User"`
	} `json:"Config"`
	HostConfig struct {
		Privileged bool `json:"Privileged"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		Ports map[string][]struct {
			HostIP   string `json:"HostIp"`
			HostPort string `json:"HostPort"`
		} `json:"Ports"`
	} `json:"NetworkSettings"`
}

// containerFindings inspects every running container for two of the most
// common ways Docker quietly undermines a host's security posture:
//
//   - Docker inserts its own iptables DNAT rules for published ports (`-p`),
//     which bypass ufw/firewalld entirely — a port that looks closed at the
//     OS firewall level can still be wide open via a container.
//   - Containers running as root (no USER set) or with --privileged have
//     little to no isolation from the host if the container is compromised.
//
// Returns no findings (not even OK) when Docker has no containers running,
// so hosts that merely have Docker installed but idle don't get noise.
func containerFindings(check string) []report.Finding {
	if !system.CommandExists("docker") {
		return nil
	}

	idsOut, err := system.Run("docker", "ps", "-q")
	if err != nil {
		return nil
	}
	ids := strings.Fields(idsOut)
	if len(ids) == 0 {
		return nil
	}

	args := append([]string{"inspect"}, ids...)
	inspectOut, err := system.Run("docker", args...)
	if err != nil {
		return nil
	}

	containers, err := parseDockerInspect(inspectOut)
	if err != nil {
		return nil
	}

	var findings []report.Finding
	for _, c := range containers {
		findings = append(findings, classifyContainer(check, c)...)
	}
	return findings
}

// parseDockerInspect parses the JSON array produced by `docker inspect`.
func parseDockerInspect(out string) ([]dockerInspectResult, error) {
	var results []dockerInspectResult
	if err := json.Unmarshal([]byte(out), &results); err != nil {
		return nil, err
	}
	return results, nil
}

// classifyContainer turns one container's inspect data into findings. Pure
// function (no I/O) so the port/root/privileged logic is testable without
// shelling out to a real Docker daemon.
func classifyContainer(check string, c dockerInspectResult) []report.Finding {
	name := strings.TrimPrefix(c.Name, "/")

	var findings []report.Finding

	if c.HostConfig.Privileged {
		findings = append(findings, report.NewFinding(check, report.CRIT,
			"container '"+name+"' is running with --privileged",
			"drop --privileged and grant only the specific capabilities the container needs (--cap-add); a privileged container has near-root access to the host", false))
	}

	if isRootUser(c.Config.User) {
		findings = append(findings, report.NewFinding(check, report.WARN,
			"container '"+name+"' has no non-root user set and runs as root inside the container",
			"set 'USER' in the image's Dockerfile or pass --user to run as an unprivileged user; a container escape lands as root on the host otherwise", false))
	}

	reported := make(map[string]bool) // host port already reported wildcard-exposed, dedupes IPv4+IPv6 bindings of the same port
	for portProto, bindings := range c.NetworkSettings.Ports {
		port, _, _ := strings.Cut(portProto, "/")
		for _, b := range bindings {
			if b.HostIP != "" && !isWildcardAddr(b.HostIP) {
				continue
			}
			if reported[b.HostPort] {
				continue
			}
			reported[b.HostPort] = true

			if svc, isDB := databasePorts[port]; isDB {
				findings = append(findings, report.NewFinding(check, report.CRIT,
					"container '"+name+"' publishes database port "+b.HostPort+" ("+svc+") to all interfaces",
					"publish it to localhost only (-p 127.0.0.1:"+b.HostPort+":"+port+") — Docker's iptables rules bypass ufw/firewalld, so the host firewall will not protect this port", false))
				continue
			}
			findings = append(findings, report.NewFinding(check, report.WARN,
				"container '"+name+"' publishes port "+b.HostPort+" to all interfaces",
				"if this doesn't need to be reachable from outside the host, bind it to localhost instead (-p 127.0.0.1:"+b.HostPort+":"+port+"); Docker's published ports are not filtered by ufw/firewalld", false))
		}
	}
	return findings
}

// isRootUser reports whether a container's Config.User value means "runs as
// root": unset, explicitly "root", or UID 0.
func isRootUser(user string) bool {
	if user == "" || user == "root" || user == "0" {
		return true
	}
	uidPart, _, _ := strings.Cut(user, ":")
	return uidPart == "0"
}

// dockerGroupFindings flags every user in the 'docker' group besides root.
// Membership is root-equivalent: the docker socket lets you bind-mount the
// host filesystem into a container and read/write anything on it, so it's
// effectively a second, unaudited sudoers list.
func dockerGroupFindings(check string) []report.Finding {
	lines, ok := system.ReadFileLines("/etc/group")
	if !ok {
		return nil
	}

	members := dockerGroupMembers(lines)
	if len(members) == 0 {
		return []report.Finding{report.NewFinding(check, report.OK,
			"no users (besides root) are in the 'docker' group", "", false)}
	}
	return []report.Finding{report.NewFinding(check, report.WARN,
		"users in the 'docker' group (root-equivalent access): "+strings.Join(members, ", "),
		"membership in the 'docker' group grants root-equivalent access to the host (e.g. 'docker run -v /:/host ...'); verify each of these users needs it", false)}
}

// dockerGroupMembers parses /etc/group and returns the members of the
// 'docker' group, excluding root (root already has unrestricted access, so
// its membership isn't worth flagging).
func dockerGroupMembers(groupLines []string) []string {
	for _, line := range groupLines {
		fields := strings.Split(line, ":")
		if len(fields) < 4 || fields[0] != "docker" {
			continue
		}
		if fields[3] == "" {
			return nil
		}
		var members []string
		for _, m := range strings.Split(fields[3], ",") {
			if m != "" && m != "root" {
				members = append(members, m)
			}
		}
		return members
	}
	return nil
}
