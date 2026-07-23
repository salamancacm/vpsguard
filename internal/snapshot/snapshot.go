// Package snapshot captures a point-in-time picture of security-relevant
// server state (users, SSH keys, cron, listening ports) so `vpsguard monitor`
// can diff it against the previous run and flag unexpected changes.
package snapshot

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/salamancacm/vpsguard/internal/system"
)

// Snapshot is a serializable picture of state that can change when a server
// is compromised: accounts, trusted SSH keys, cron jobs, open ports.
type Snapshot struct {
	Timestamp      time.Time           `json:"timestamp"`
	Users          []string            `json:"users"`           // "name:uid"
	UID0Users      []string            `json:"uid0_users"`      // extra UID 0 accounts besides root
	SudoersEntries []string            `json:"sudoers_entries"` // /etc/sudoers.d/*
	AuthorizedKeys map[string][]string `json:"authorized_keys"` // user -> authorized_keys lines
	ListeningPorts []string            `json:"listening_ports"` // local ports from `ss -tulnp`
	CronEntries    map[string][]string `json:"cron_entries"`    // user -> crontab lines
	RootProcesses  []string            `json:"root_processes"`  // distinct command names running as root
}

// Capture builds a fresh Snapshot from current system state.
func Capture() Snapshot {
	s := Snapshot{
		Timestamp:      time.Now().UTC(),
		AuthorizedKeys: map[string][]string{},
		CronEntries:    map[string][]string{},
	}

	s.Users, s.UID0Users = captureUsers()
	s.SudoersEntries, _ = system.ListDir("/etc/sudoers.d")
	sort.Strings(s.SudoersEntries)

	for user, home := range system.RealUserHomes() {
		akPath := filepath.Join(home, ".ssh", "authorized_keys")
		if lines, ok := system.ReadFileLines(akPath); ok {
			s.AuthorizedKeys[user] = lines
		}

		out, err := system.Run("crontab", "-l", "-u", user)
		if err == nil {
			var entries []string
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				entries = append(entries, line)
			}
			if len(entries) > 0 {
				s.CronEntries[user] = entries
			}
		}
	}

	s.ListeningPorts = captureListeningPorts()
	s.RootProcesses = captureRootProcesses()

	return s
}

func captureUsers() (all []string, uid0 []string) {
	lines, ok := system.ReadFileLines("/etc/passwd")
	if !ok {
		return nil, nil
	}
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		name, uidStr := fields[0], fields[2]
		all = append(all, name+":"+uidStr)

		uid, err := strconv.Atoi(uidStr)
		if err == nil && uid == 0 && name != "root" {
			uid0 = append(uid0, name)
		}
	}
	sort.Strings(all)
	sort.Strings(uid0)
	return all, uid0
}

func captureListeningPorts() []string {
	if !system.CommandExists("ss") {
		return nil
	}
	out, err := system.Run("ss", "-tuln")
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var ports []string
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		addr := fields[4]
		idx := strings.LastIndex(addr, ":")
		if idx == -1 {
			continue
		}
		port := addr[idx+1:]
		if port == "" || seen[port] {
			continue
		}
		if _, err := strconv.Atoi(port); err != nil {
			continue
		}
		seen[port] = true
		ports = append(ports, port)
	}
	sort.Strings(ports)
	return ports
}

// captureRootProcesses returns the distinct command names (not PIDs, which
// churn constantly and would make every snapshot look "new") of processes
// currently running as root. Reads /proc directly instead of shelling out
// to `ps`, whose column layout varies across distros/versions.
func captureRootProcesses() []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}

	seen := map[string]bool{}
	var names []string
	for _, e := range entries {
		pid := e.Name()
		if _, err := strconv.Atoi(pid); err != nil {
			continue // not a PID directory (e.g. /proc/net, /proc/self)
		}

		statusLines, ok := system.ReadFileLines(filepath.Join("/proc", pid, "status"))
		if !ok || !isRootProcess(statusLines) {
			continue
		}

		commLines, ok := system.ReadFileLines(filepath.Join("/proc", pid, "comm"))
		if !ok || len(commLines) == 0 {
			continue
		}

		name := commLines[0]
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	sort.Strings(names)
	return names
}

// isRootProcess parses the "Uid:" line of /proc/<pid>/status. The four
// fields are real, effective, saved, and filesystem UID; a process is
// treated as root only if the effective UID (the second field) is 0.
func isRootProcess(statusLines []string) bool {
	for _, line := range statusLines {
		if !strings.HasPrefix(line, "Uid:") {
			continue
		}
		fields := strings.Fields(line)
		return len(fields) >= 3 && fields[2] == "0"
	}
	return false
}
