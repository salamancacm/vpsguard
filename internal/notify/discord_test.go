package notify

import (
	"testing"

	"github.com/salamancacm/vpsguard/internal/report"
)

func TestDiscordColor(t *testing.T) {
	tests := []struct {
		sev  report.Severity
		want int
	}{
		{report.OK, 0x2ECC71},
		{report.WARN, 0xF39C12},
		{report.CRIT, 0xE74C3C},
	}
	for _, tt := range tests {
		if got := discordColor(tt.sev); got != tt.want {
			t.Errorf("discordColor(%v) = %#x, want %#x", tt.sev, got, tt.want)
		}
	}
}
