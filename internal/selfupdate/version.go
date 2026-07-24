// Package selfupdate implements `vpsguard update`: checking whether a
// newer release exists and, if asked, downloading and installing it in
// place. It shares install.sh's design goals (arch detection, mandatory
// checksum verification against the published release) but is
// implemented in Go rather than shell since it runs from inside an
// already-running vpsguard binary.
package selfupdate

import (
	"fmt"
	"strconv"
	"strings"
)

// ParseVersion parses a "vX.Y.Z" tag into its numeric components.
func ParseVersion(s string) (major, minor, patch int, err error) {
	s = strings.TrimPrefix(s, "v")
	parts := strings.SplitN(s, ".", 3)
	if len(parts) != 3 {
		return 0, 0, 0, fmt.Errorf("not a vX.Y.Z version: %q", s)
	}
	nums := make([]int, 3)
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return 0, 0, 0, fmt.Errorf("not a vX.Y.Z version: %q", s)
		}
		nums[i] = n
	}
	return nums[0], nums[1], nums[2], nil
}

// IsNewer reports whether latest is a strictly newer version than
// current. Either version failing to parse (e.g. "dev", used for local
// non-release builds — see cmd.Version's doc comment) returns false: an
// unparseable version never triggers an update prompt off garbage.
func IsNewer(current, latest string) bool {
	cMaj, cMin, cPat, err := ParseVersion(current)
	if err != nil {
		return false
	}
	lMaj, lMin, lPat, err := ParseVersion(latest)
	if err != nil {
		return false
	}

	if lMaj != cMaj {
		return lMaj > cMaj
	}
	if lMin != cMin {
		return lMin > cMin
	}
	return lPat > cPat
}
