package checks

import (
	"os"
	"testing"

	"github.com/salamancacm/vpsguard/internal/report"
)

func TestSocketPermissionFinding(t *testing.T) {
	tests := []struct {
		name string
		perm os.FileMode
		want report.Severity
	}{
		{"standard 0660", 0o660, report.OK},
		{"world-writable 0666", 0o666, report.CRIT},
		{"world-writable 0662", 0o662, report.CRIT},
		{"looser but not world-writable, 0664", 0o664, report.WARN},
		{"looser but not world-writable, 0640", 0o640, report.WARN},
		{"tighter than default, 0600", 0o600, report.OK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := socketPermissionFinding("docker", tt.perm)
			if got.Severity != tt.want {
				t.Errorf("socketPermissionFinding(%v).Severity = %v, want %v", tt.perm, got.Severity, tt.want)
			}
		})
	}
}

func TestHasInsecureTCPListener(t *testing.T) {
	tests := []struct {
		name string
		out  string
		want bool
	}{
		{
			name: "dockerd listening on 2375",
			out: `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
tcp   LISTEN 0      4096         0.0.0.0:2375      0.0.0.0:*    users:(("dockerd",pid=1,fd=7))`,
			want: true,
		},
		{
			name: "only ssh listening",
			out: `Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess
tcp   LISTEN 0      128          0.0.0.0:22        0.0.0.0:*    users:(("sshd",pid=1,fd=3))`,
			want: false,
		},
		{
			name: "no listeners at all",
			out:  "Netid State  Recv-Q Send-Q Local Address:Port Peer Address:PortProcess",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := hasInsecureTCPListener(tt.out); got != tt.want {
				t.Errorf("hasInsecureTCPListener(%q) = %v, want %v", tt.out, got, tt.want)
			}
		})
	}
}
