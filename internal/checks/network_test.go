package checks

import (
	"reflect"
	"sort"
	"testing"
)

// Fixtures below are captured verbatim from real `ss -tulnp` runs during
// manual testing (see PR history) rather than hand-typed, specifically
// because a hand-typed fixture would have missed the column-count bug
// that shipped in docker.go's first version (mixing up `ss -tln` output,
// which lacks the Netid column, with `ss -tulnp`'s layout).
func TestParseListeners(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want []listener
	}{
		{
			name: "real ss -tulnp output, ipv4 and ipv6",
			out: `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=1,fd=3))
tcp   LISTEN 0      511              *:80              *:*    users:(("nginx",pid=10,fd=6))
tcp   LISTEN 0      4096       127.0.0.1:6379     0.0.0.0:*    users:(("redis-server",pid=20,fd=6))
tcp   LISTEN 0      128             [::]:22           [::]:*    users:(("sshd",pid=1,fd=4))`,
			want: []listener{
				{addr: "0.0.0.0", port: "22"},
				{addr: "*", port: "80"},
				{addr: "127.0.0.1", port: "6379"},
				{addr: "::", port: "22"},
			},
		},
		{
			name: "duplicate address:port pairs are deduplicated",
			out: `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
tcp   LISTEN 0      1            0.0.0.0:2375      0.0.0.0:*    users:(("nc",pid=1,fd=3))
tcp   LISTEN 0      1            0.0.0.0:2375      0.0.0.0:*    users:(("nc",pid=2,fd=3))`,
			want: []listener{
				{addr: "0.0.0.0", port: "2375"},
			},
		},
		{
			name: "header-only output has no listeners",
			out:  "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess",
			want: nil,
		},
		{
			name: "empty output",
			out:  "",
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseListeners(tt.out)
			sortListeners(got)
			sortListeners(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseListeners(%q) = %+v, want %+v", tt.out, got, tt.want)
			}
		})
	}
}

func sortListeners(l []listener) {
	sort.Slice(l, func(i, j int) bool {
		if l[i].port != l[j].port {
			return l[i].port < l[j].port
		}
		return l[i].addr < l[j].addr
	})
}

func TestIsWildcardAddr(t *testing.T) {
	tests := map[string]bool{
		"0.0.0.0":     true,
		"::":          true,
		"*":           true,
		"127.0.0.1":   false,
		"::1":         false,
		"10.0.0.5":    false,
		"192.168.1.1": false,
	}
	for addr, want := range tests {
		if got := isWildcardAddr(addr); got != want {
			t.Errorf("isWildcardAddr(%q) = %v, want %v", addr, got, want)
		}
	}
}

func TestIsDigits(t *testing.T) {
	tests := map[string]bool{
		"22":  true,
		"0":   true,
		"":    false,
		"22a": false,
		"-22": false,
		"2 2": false,
	}
	for s, want := range tests {
		if got := isDigits(s); got != want {
			t.Errorf("isDigits(%q) = %v, want %v", s, got, want)
		}
	}
}
