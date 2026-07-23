package harden

import (
	"bufio"
	"os"
	"strings"
)

// SetDirective ensures `key value` appears exactly once, active, in a
// space-separated config file like sshd_config. Existing occurrences
// (commented or not) are replaced in place; if none exist, the directive is
// appended. Returns true if the file content changed.
func SetDirective(path, key, value string) (changed bool, err error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	var lines []string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	f.Close()
	if err := sc.Err(); err != nil {
		return false, err
	}

	target := key + " " + value
	found := false
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		bare := strings.TrimPrefix(trimmed, "#")
		bare = strings.TrimSpace(bare)
		fields := strings.Fields(bare)
		if len(fields) == 0 || !strings.EqualFold(fields[0], key) {
			continue
		}
		found = true
		if trimmed == target {
			continue // already correct and active
		}
		lines[i] = target
		changed = true
	}

	if !found {
		lines = append(lines, target)
		changed = true
	}

	if !changed {
		return false, nil
	}

	out, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return false, err
	}
	defer out.Close()

	w := bufio.NewWriter(out)
	for _, line := range lines {
		if _, err := w.WriteString(line + "\n"); err != nil {
			return false, err
		}
	}
	return true, w.Flush()
}
