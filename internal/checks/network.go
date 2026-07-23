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

// databasePorts are well-known database/datastore ports that should almost
// never be reachable from outside the host. Finding one bound to a
// wildcard address is one of the most common real-world VPS compromise
// vectors (unauthenticated Redis/Mongo exposed to the internet, etc.).
var databasePorts = map[string]string{
	"5432":  "postgresql",
	"3306":  "mysql/mariadb",
	"6379":  "redis",
	"27017": "mongodb",
	"9200":  "elasticsearch",
}

// Network lists TCP/UDP ports in LISTEN state via `ss` and flags anything
// outside the small set of standard ports as worth a second look. Database
// ports bound to a wildcard address get their own, more severe finding.
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

	listeners := parseListeners(out)
	if len(listeners) == 0 {
		return []report.Finding{report.NewFinding(check, report.OK,
			"no listening ports detected", "", false)}
	}

	var findings []report.Finding
	for _, l := range listeners {
		if svc, isDB := databasePorts[l.port]; isDB && isWildcardAddr(l.addr) {
			findings = append(findings, report.NewFinding(check, report.CRIT,
				"database port "+l.port+" ("+svc+") is listening on all interfaces ("+l.addr+")",
				"bind "+svc+" to 127.0.0.1 (or a private interface behind a firewall) unless it truly needs to be reachable from outside the host", false))
			continue
		}

		if svc, known := standardPorts[l.port]; known {
			findings = append(findings, report.NewFinding(check, report.OK,
				"port "+l.port+" ("+svc+") is listening", "", false))
		} else {
			findings = append(findings, report.NewFinding(check, report.WARN,
				"non-standard port listening: "+l.port+" (verify this is an expected service)",
				"", false))
		}
	}
	return findings
}

type listener struct {
	addr string
	port string
}

// parseListeners extracts the unique (address, port) pairs from `ss -tulnp`
// output (the "Local Address:Port" column, splitting on the last colon so
// IPv6 addresses like [::]:22 parse correctly).
func parseListeners(out string) []listener {
	seen := make(map[listener]bool)
	var listeners []listener

	lines := strings.Split(out, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		// Header row starts with "Netid"; local address is typically field[4].
		local := fields[4]
		idx := strings.LastIndex(local, ":")
		if idx == -1 {
			continue
		}
		addr := strings.Trim(local[:idx], "[]")
		port := local[idx+1:]
		if port == "" || !isDigits(port) {
			continue
		}

		l := listener{addr: addr, port: port}
		if !seen[l] {
			seen[l] = true
			listeners = append(listeners, l)
		}
	}
	return listeners
}

// isWildcardAddr reports whether addr means "all interfaces" rather than a
// specific one (loopback or otherwise).
func isWildcardAddr(addr string) bool {
	switch addr {
	case "0.0.0.0", "::", "*":
		return true
	default:
		return false
	}
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}
