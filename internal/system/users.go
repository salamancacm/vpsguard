package system

import (
	"strconv"
	"strings"
)

// RealUserHomes returns login-capable, human accounts (UID >= 1000, plus
// root) mapped to their home directory, by parsing /etc/passwd.
func RealUserHomes() map[string]string {
	lines, ok := ReadFileLines("/etc/passwd")
	if !ok {
		return nil
	}

	homes := make(map[string]string)
	for _, line := range lines {
		fields := strings.Split(line, ":")
		if len(fields) < 7 {
			continue
		}
		name, uidStr, home, shell := fields[0], fields[2], fields[5], fields[6]
		if strings.HasSuffix(shell, "nologin") || strings.HasSuffix(shell, "/false") {
			continue
		}
		uid, err := strconv.Atoi(uidStr)
		if err != nil {
			continue
		}
		if uid == 0 || uid >= 1000 {
			homes[name] = home
		}
	}
	return homes
}
