package checks

import "testing"

func TestIsAutoUpgradesEnabled(t *testing.T) {
	tests := []struct {
		name  string
		lines []string
		want  bool
	}{
		{
			name: "enabled",
			lines: []string{
				`APT::Periodic::Update-Package-Lists "1";`,
				`APT::Periodic::Unattended-Upgrade "1";`,
			},
			want: true,
		},
		{
			name: "disabled",
			lines: []string{
				`APT::Periodic::Update-Package-Lists "1";`,
				`APT::Periodic::Unattended-Upgrade "0";`,
			},
			want: false,
		},
		{
			name:  "missing directive",
			lines: []string{`APT::Periodic::Update-Package-Lists "1";`},
			want:  false,
		},
		{
			name:  "empty file",
			lines: nil,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isAutoUpgradesEnabled(tt.lines); got != tt.want {
				t.Errorf("isAutoUpgradesEnabled(%v) = %v, want %v", tt.lines, got, tt.want)
			}
		})
	}
}
