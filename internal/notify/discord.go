package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/salamancacm/vpsguard/internal/report"
)

// DiscordNotifier posts findings to a Discord webhook as a colored embed
// (red for CRIT, orange for WARN) instead of WebhookNotifier's plain
// "content" field.
type DiscordNotifier struct {
	URL string

	httpClient *http.Client
}

// NewDiscordNotifier returns a DiscordNotifier posting to a Discord webhook
// URL (https://discord.com/api/webhooks/...).
func NewDiscordNotifier(url string) *DiscordNotifier {
	return &DiscordNotifier{
		URL:        url,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// discordPayload mirrors the subset of Discord's webhook embed format this
// notifier uses. See: https://discord.com/developers/docs/resources/webhook
type discordPayload struct {
	Embeds []discordEmbed `json:"embeds"`
}

type discordEmbed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Color       int    `json:"color"`
}

func (d *DiscordNotifier) Notify(findings []report.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	payload := discordPayload{Embeds: []discordEmbed{{
		Title:       fmt.Sprintf("vpsguard monitor detected %d change(s)", len(findings)),
		Description: findingsList(findings),
		Color:       discordColor(maxSeverity(findings)),
	}}}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding Discord payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, d.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building Discord request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := d.httpClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending Discord notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("Discord webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// discordColor maps a severity to a Discord embed color (a plain decimal
// RGB integer, not a hex string).
func discordColor(sev report.Severity) int {
	switch sev {
	case report.CRIT:
		return 0xE74C3C // red
	case report.WARN:
		return 0xF39C12 // orange
	default:
		return 0x2ECC71 // green
	}
}
