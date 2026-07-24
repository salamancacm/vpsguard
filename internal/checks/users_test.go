package checks

import "testing"

func TestUID0AccountsBesidesRoot(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  []string
	}{
		{
			name: "only root has UID 0",
			lines: []string{
				"root:x:0:0:root:/root:/bin/bash",
				"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
			},
			want: nil,
		},
		{
			name: "backdoor account with UID 0",
			lines: []string{
				"root:x:0:0:root:/root:/bin/bash",
				"backdoor:x:0:0:backdoor:/home/backdoor:/bin/bash",
			},
			want: []string{"backdoor"},
		},
		{
			name:  "malformed line is skipped, not a crash",
			lines: []string{"not:a:valid:passwd:line:with:enough:fields:but:non-numeric:uid"},
			want:  nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uid0AccountsBesidesRoot(tt.lines)
			if len(got) != len(tt.want) {
				t.Fatalf("uid0AccountsBesidesRoot(%v) = %v, want %v", tt.lines, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("uid0AccountsBesidesRoot(%v) = %v, want %v", tt.lines, got, tt.want)
				}
			}
		})
	}
}

func TestEmptyPasswordAccounts(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  []string
	}{
		{
			name: "all accounts locked or have a hash",
			lines: []string{
				"root:$6$abc123:19700:0:99999:7:::",
				"nobody:*:19700:0:99999:7:::",
			},
			want: nil,
		},
		{
			name: "one account with an empty password field",
			lines: []string{
				"root:$6$abc123:19700:0:99999:7:::",
				"guest::19700:0:99999:7:::",
			},
			want: []string{"guest"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := emptyPasswordAccounts(tt.lines)
			if len(got) != len(tt.want) {
				t.Fatalf("emptyPasswordAccounts(%v) = %v, want %v", tt.lines, got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("emptyPasswordAccounts(%v) = %v, want %v", tt.lines, got, tt.want)
				}
			}
		})
	}
}
