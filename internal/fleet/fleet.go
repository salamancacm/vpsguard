// Package fleet runs `vpsguard audit --json` on remote hosts over SSH and
// aggregates the results. It shells out to the system `ssh` binary rather
// than using an SSH client library, so it transparently reuses whatever
// keys, agent, and ~/.ssh/config the operator already has working —
// consistent with how the rest of vpsguard prefers shelling out to real
// tools (ufw, fail2ban-client, ...) over reimplementing their logic.
//
// Prerequisite: vpsguard must already be installed on each remote host
// (see install.sh), and the SSH user must have enough privilege to run
// `vpsguard audit` meaningfully — a non-root user without sudo will still
// get a valid audit, just with the same "could not read /etc/shadow"-style
// WARNs a local non-root run would produce. Bootstrapping/installing
// vpsguard remotely is out of scope for this package.
package fleet

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"sync"

	"github.com/salamancacm/vpsguard/internal/config"
	"github.com/salamancacm/vpsguard/internal/report"
)

const defaultConcurrency = 5

// HostResult is one host's outcome: either Findings (on success) or Error
// (on any failure — SSH connection, non-zero exit, unparseable output),
// never both.
type HostResult struct {
	Host     string           `json:"host"`
	Addr     string           `json:"addr"`
	Findings []report.Finding `json:"findings,omitempty"`
	Error    string           `json:"error,omitempty"`
}

// Run audits every host in hosts concurrently (bounded by concurrency;
// <=0 uses a sane default) and returns one HostResult per host, in the
// same order as hosts.
func Run(hosts []config.HostConfig, concurrency int) []HostResult {
	if concurrency <= 0 {
		concurrency = defaultConcurrency
	}

	results := make([]HostResult, len(hosts))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup

	for i, h := range hosts {
		wg.Add(1)
		go func(i int, h config.HostConfig) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[i] = auditHost(h)
		}(i, h)
	}

	wg.Wait()
	return results
}

func auditHost(h config.HostConfig) HostResult {
	name := hostDisplayName(h)
	result := HostResult{Host: name, Addr: h.Addr}

	out, err := exec.Command("ssh", sshArgs(h)...).Output()
	if err != nil {
		result.Error = fmt.Sprintf("ssh to %s failed: %v", h.Addr, err)
		return result
	}

	var findings []report.Finding
	if err := json.Unmarshal(out, &findings); err != nil {
		result.Error = fmt.Sprintf("parsing 'vpsguard audit --json' output from %s: %v (is vpsguard installed and on PATH there?)", h.Addr, err)
		return result
	}

	result.Findings = findings
	return result
}

// hostDisplayName returns h.Name, falling back to h.Addr when unset.
func hostDisplayName(h config.HostConfig) string {
	if h.Name != "" {
		return h.Name
	}
	return h.Addr
}

// sshArgs builds the ssh command line for auditing h. Defaults the port
// to 22 when unset.
func sshArgs(h config.HostConfig) []string {
	port := h.Port
	if port == 0 {
		port = 22
	}
	return []string{
		"-o", "BatchMode=yes", // never prompt for a password — fail fast instead
		"-o", "ConnectTimeout=10",
		"-o", "StrictHostKeyChecking=accept-new", // trust new hosts, still detect a changed key later
		"-p", strconv.Itoa(port),
		h.User + "@" + h.Addr,
		"vpsguard", "audit", "--json",
	}
}
