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

func TestIsRootUser(t *testing.T) {
	tests := []struct {
		user string
		want bool
	}{
		{"", true},
		{"root", true},
		{"0", true},
		{"0:0", true},
		{"app", false},
		{"1000", false},
		{"1000:1000", false},
	}

	for _, tt := range tests {
		t.Run(tt.user, func(t *testing.T) {
			if got := isRootUser(tt.user); got != tt.want {
				t.Errorf("isRootUser(%q) = %v, want %v", tt.user, got, tt.want)
			}
		})
	}
}

func TestDockerGroupMembers(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  []string
	}{
		{
			name: "no docker group at all",
			lines: []string{
				"root:x:0:",
				"sudo:x:27:carlos",
			},
			want: nil,
		},
		{
			name: "docker group with no members",
			lines: []string{
				"docker:x:999:",
			},
			want: nil,
		},
		{
			name: "docker group with members, root excluded",
			lines: []string{
				"docker:x:999:root,carlos,deploy",
			},
			want: []string{"carlos", "deploy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dockerGroupMembers(tt.lines)
			if len(got) != len(tt.want) {
				t.Fatalf("dockerGroupMembers(%v) = %v, want %v", tt.lines, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("dockerGroupMembers(%v) = %v, want %v", tt.lines, got, tt.want)
				}
			}
		})
	}
}

func TestClassifyContainer(t *testing.T) {
	tests := []struct {
		name        string
		inspectJSON string
		wantSevs    []report.Severity
	}{
		{
			name: "privileged root container publishing a database port",
			inspectJSON: `[{
				"Name": "/redis",
				"Config": {"User": ""},
				"HostConfig": {"Privileged": true},
				"NetworkSettings": {"Ports": {"6379/tcp": [{"HostIp": "0.0.0.0", "HostPort": "6379"}]}}
			}]`,
			wantSevs: []report.Severity{report.CRIT, report.WARN, report.CRIT},
		},
		{
			name: "non-root container publishing an ordinary port to localhost only",
			inspectJSON: `[{
				"Name": "/web",
				"Config": {"User": "1000:1000"},
				"HostConfig": {"Privileged": false},
				"NetworkSettings": {"Ports": {"8080/tcp": [{"HostIp": "127.0.0.1", "HostPort": "8080"}]}}
			}]`,
			wantSevs: nil,
		},
		{
			name: "root container publishing an ordinary port to all interfaces",
			inspectJSON: `[{
				"Name": "/web",
				"Config": {"User": "root"},
				"HostConfig": {"Privileged": false},
				"NetworkSettings": {"Ports": {"8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}]}}
			}]`,
			wantSevs: []report.Severity{report.WARN, report.WARN},
		},
		{
			name: "unpublished port (bound to nothing) produces no port finding",
			inspectJSON: `[{
				"Name": "/db",
				"Config": {"User": "app"},
				"HostConfig": {"Privileged": false},
				"NetworkSettings": {"Ports": {"5432/tcp": null}}
			}]`,
			wantSevs: nil,
		},
		{
			name: "same port bound to both IPv4 and IPv6 wildcard produces one finding, not two",
			inspectJSON: `[{
				"Name": "/web",
				"Config": {"User": "app"},
				"HostConfig": {"Privileged": false},
				"NetworkSettings": {"Ports": {"80/tcp": [{"HostIp": "0.0.0.0", "HostPort": "8080"}, {"HostIp": "::", "HostPort": "8080"}]}}
			}]`,
			wantSevs: []report.Severity{report.WARN},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			containers, err := parseDockerInspect(tt.inspectJSON)
			if err != nil {
				t.Fatalf("parseDockerInspect: %v", err)
			}
			if len(containers) != 1 {
				t.Fatalf("expected 1 container, got %d", len(containers))
			}

			findings := classifyContainer("docker", containers[0])
			if len(findings) != len(tt.wantSevs) {
				t.Fatalf("got %d findings, want %d (%+v)", len(findings), len(tt.wantSevs), findings)
			}
			for i, want := range tt.wantSevs {
				if findings[i].Severity != want {
					t.Errorf("finding %d severity = %v, want %v", i, findings[i].Severity, want)
				}
			}
		})
	}
}
