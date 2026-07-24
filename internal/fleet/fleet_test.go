package fleet

import (
	"reflect"
	"testing"

	"github.com/salamancacm/vpsguard/internal/config"
)

func TestHostDisplayName(t *testing.T) {
	tests := []struct {
		h    config.HostConfig
		want string
	}{
		{config.HostConfig{Name: "web-1", Addr: "203.0.113.10"}, "web-1"},
		{config.HostConfig{Addr: "203.0.113.10"}, "203.0.113.10"},
	}
	for _, tt := range tests {
		if got := hostDisplayName(tt.h); got != tt.want {
			t.Errorf("hostDisplayName(%+v) = %q, want %q", tt.h, got, tt.want)
		}
	}
}

func TestSSHArgs_DefaultsPortTo22(t *testing.T) {
	h := config.HostConfig{Addr: "203.0.113.10", User: "root"}
	args := sshArgs(h)

	if !containsSeq(args, []string{"-p", "22"}) {
		t.Errorf("sshArgs(%+v) = %v, want it to default the port to 22", h, args)
	}
	if !containsSeq(args, []string{"root@203.0.113.10"}) {
		t.Errorf("sshArgs(%+v) = %v, missing the expected user@addr target", h, args)
	}
	if !containsSeq(args, []string{"vpsguard", "audit", "--json"}) {
		t.Errorf("sshArgs(%+v) = %v, missing the expected remote command", h, args)
	}
}

func TestSSHArgs_RespectsCustomPort(t *testing.T) {
	h := config.HostConfig{Addr: "203.0.113.10", User: "deploy", Port: 2222}
	args := sshArgs(h)

	if !containsSeq(args, []string{"-p", "2222"}) {
		t.Errorf("sshArgs(%+v) = %v, want the custom port 2222", h, args)
	}
}

func TestSSHArgs_NeverPromptsForAPassword(t *testing.T) {
	// BatchMode=yes is what makes a fleet run against an unreachable/
	// unauthenticated host fail fast instead of hanging on a password
	// prompt that will never be answered.
	args := sshArgs(config.HostConfig{Addr: "203.0.113.10", User: "root"})
	if !containsSeq(args, []string{"-o", "BatchMode=yes"}) {
		t.Errorf("sshArgs() = %v, missing BatchMode=yes", args)
	}
}

// containsSeq reports whether seq appears as a contiguous subsequence of s.
func containsSeq(s, seq []string) bool {
	if len(seq) == 0 || len(seq) > len(s) {
		return false
	}
	for i := 0; i+len(seq) <= len(s); i++ {
		if reflect.DeepEqual(s[i:i+len(seq)], seq) {
			return true
		}
	}
	return false
}
