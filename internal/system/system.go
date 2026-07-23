// Package system provides small helpers for talking to the host OS:
// running commands, checking privileges, and detecting the Linux distro.
package system

import (
	"bufio"
	"os"
	"os/exec"
	"runtime"
	"strings"
)

// IsRoot reports whether the current process is running as root.
// Always false on non-Linux hosts (used for local dev/testing on Windows).
func IsRoot() bool {
	if runtime.GOOS != "linux" {
		return false
	}
	return os.Geteuid() == 0
}

// IsLinux reports whether vpsguard is running on its supported target OS.
func IsLinux() bool {
	return runtime.GOOS == "linux"
}

// Run executes a command and returns its combined stdout, ignoring a
// non-zero exit code (callers check the returned error separately via RunErr
// when the exit code matters).
func Run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// CommandExists reports whether a binary is available on PATH.
func CommandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// ReadFileLines reads a file and returns its non-empty, non-comment lines.
// Returns (nil, false) if the file does not exist or cannot be read.
func ReadFileLines(path string) ([]string, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		lines = append(lines, line)
	}
	return lines, true
}

// ListDir returns the names of entries in a directory, excluding "." files
// like README that packages sometimes drop in sudoers.d.
func ListDir(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".") || e.Name() == "README" {
			continue
		}
		names = append(names, e.Name())
	}
	return names, nil
}

// DistroID returns the ID field from /etc/os-release (e.g. "ubuntu", "debian",
// "rhel"), or "" if it cannot be determined.
func DistroID() string {
	lines, ok := ReadFileLines("/etc/os-release")
	if !ok {
		return ""
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "ID=") {
			id := strings.TrimPrefix(line, "ID=")
			return strings.Trim(id, `"`)
		}
	}
	return ""
}

// PackageFamily buckets a distro ID into "debian" or "rhel" so checks can
// pick the right service/package manager names. Returns "" if unknown.
func PackageFamily() string {
	switch DistroID() {
	case "ubuntu", "debian":
		return "debian"
	case "rhel", "centos", "fedora", "rocky", "almalinux":
		return "rhel"
	default:
		return ""
	}
}
