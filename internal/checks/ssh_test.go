package checks

import "testing"

func TestParseSSHDConfig(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  map[string]string
	}{
		{
			name:  "empty file",
			lines: nil,
			want:  map[string]string{},
		},
		{
			name: "typical config",
			lines: []string{
				"Port 22",
				"PermitRootLogin no",
				"PasswordAuthentication yes",
			},
			want: map[string]string{
				"port":                   "22",
				"permitrootlogin":        "no",
				"passwordauthentication": "yes",
			},
		},
		{
			name: "keys are case-insensitive, values are lowercased",
			lines: []string{
				"PermitRootLogin NO",
				"Port 2222",
			},
			want: map[string]string{
				"permitrootlogin": "no",
				"port":            "2222",
			},
		},
		{
			name: "first occurrence wins (sshd_config semantics)",
			lines: []string{
				"PermitRootLogin no",
				"PermitRootLogin yes",
			},
			want: map[string]string{
				"permitrootlogin": "no",
			},
		},
		{
			name:  "malformed line with no value is skipped",
			lines: []string{"PermitRootLogin"},
			want:  map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseSSHDConfig(tt.lines)
			if len(got) != len(tt.want) {
				t.Fatalf("parseSSHDConfig(%v) = %v, want %v", tt.lines, got, tt.want)
			}
			for k, v := range tt.want {
				if got[k] != v {
					t.Errorf("parseSSHDConfig(%v)[%q] = %q, want %q", tt.lines, k, got[k], v)
				}
			}
		})
	}
}
