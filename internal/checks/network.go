package checks

import (
	"strings"

	"github.com/salamancacm/vpsguard/internal/report"
	"github.com/salamancacm/vpsguard/internal/system"
)

// standardPorts are common, expected services; anything else listening is
// flagged as informational so the human can decide if it's legitimate.
var standardPorts = map[string]string{
	"22":  "ssh",
	"80":  "http",
	"443": "https",
}

// Network lists TCP/UDP ports in LISTEN state via `ss` and flags anything
// outside the small set of standard ports as worth a second look.
func Network() []report.Finding {
	const check = "network"

	if !system.CommandExists("ss") {
		return []report.Finding{report.NewFinding(check, report.WARN,
			"the 'ss' command is not available, could not audit listening ports", "", false)}
	}

	out, err := system.Run("ss", "-tulnp")
	if err != nil {
		return []report.Finding{report.NewFinding(check, report.WARN,
			"could not run 'ss -tulnp'", "", false)}
	}

	ports := parseListeningPorts(out)
	if len(ports) == 0 {
		return []report.Finding{report.NewFinding(check, report.OK,
			"no listening ports detected", "", false)}
	}

	var findings []report.Finding
	for _, p := range ports {
		if svc, known := standardPorts[p]; known {
			findings = append(findings, report.NewFinding(check, report.OK,
				"port "+p+" ("+svc+") is listening", "", false))
		} else {
			findings = append(findings, report.NewFinding(check, report.WARN,
				"non-standard port listening: "+p+" (verify this is an expected service)",
				"", false))
		}
	}
	return findings
}

// parseListeningPorts extracts the unique local ports from `ss -tulnp`
// output (the "Local Address:Port" column, taking the text after the last
// colon so IPv6 addresses like [::]:22 parse correctly).
func parseListeningPorts(out string) []string {
	seen := make(map[string]bool)
	var ports []string

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Header row starts with "Netid"; local address is typically field[4].
		addr := fields[4]
		idx := strings.LastIndex(addr, ":")
		if idx == -1 {
			continue
		}
		port := addr[idx+1:]
		if port == "" || !isDigits(port) {
			continue
		}
		if !seen[port] {
			seen[port] = true
			ports = append(ports, port)
		}
	}
	return ports
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}
