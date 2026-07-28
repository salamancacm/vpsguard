package notify

import (
	"testing"

	"github.com/salamancacm/vpsguard/internal/report"
)

func TestSlackColor(t *testing.T) {
	tests := []struct {
		sev  report.Severity
		want string
	}{
		{report.OK, "good"},
		{report.WARN, "warning"},
		{report.CRIT, "danger"},
	}
	for _, tt := range tests {
		if got := slackColor(tt.sev); got != tt.want {
			t.Errorf("slackColor(%v) = %q, want %q", tt.sev, got, tt.want)
		}
	}
}
