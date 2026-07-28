package report

import "testing"

func TestScore(t *testing.T) {
	tests := []struct {
		name     string
		findings []Finding
		want     int
	}{
		{
			name:     "no findings at all is a perfect score",
			findings: nil,
			want:     100,
		},
		{
			name: "all OK",
			findings: []Finding{
				NewFinding("ssh", OK, "", "", false),
				NewFinding("firewall", OK, "", "", false),
			},
			want: 100,
		},
		{
			name: "all CRIT",
			findings: []Finding{
				NewFinding("ssh", CRIT, "", "", false),
				NewFinding("firewall", CRIT, "", "", false),
			},
			want: 0,
		},
		{
			name: "WARN earns half credit",
			findings: []Finding{
				NewFinding("ssh", OK, "", "", false),
				NewFinding("firewall", WARN, "", "", false),
			},
			want: 75,
		},
		{
			name: "mix of everything",
			findings: []Finding{
				NewFinding("ssh", OK, "", "", false),
				NewFinding("firewall", OK, "", "", false),
				NewFinding("fail2ban", WARN, "", "", false),
				NewFinding("users", CRIT, "", "", false),
			},
			want: 63, // (1 + 1 + 0.5 + 0) / 4 * 100 = 62.5, rounds to 63
		},
		{
			name: "acknowledged findings are excluded from the score",
			findings: []Finding{
				NewFinding("ssh", OK, "", "", false),
				func() Finding {
					f := NewFinding("firewall", CRIT, "", "", false)
					f.Acknowledged = true
					return f
				}(),
			},
			want: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Score(tt.findings); got != tt.want {
				t.Errorf("Score(%v) = %d, want %d", tt.findings, got, tt.want)
			}
		})
	}
}

func TestScoreLabel(t *testing.T) {
	tests := []struct {
		score int
		want  string
	}{
		{100, "Good"},
		{90, "Good"},
		{89, "Needs attention"},
		{70, "Needs attention"},
		{69, "Critical"},
		{0, "Critical"},
	}

	for _, tt := range tests {
		if got := ScoreLabel(tt.score); got != tt.want {
			t.Errorf("ScoreLabel(%d) = %q, want %q", tt.score, got, tt.want)
		}
	}
}
