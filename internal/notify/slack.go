package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/salamancacm/vpsguard/internal/report"
)

// SlackNotifier posts findings to a Slack incoming webhook as a colored
// attachment (red for CRIT, yellow for WARN) instead of WebhookNotifier's
// plain "text" field, so a bad finding actually stands out in the channel.
type SlackNotifier struct {
	URL string

	httpClient *http.Client
}

// NewSlackNotifier returns a SlackNotifier posting to a Slack incoming
// webhook URL (https://hooks.slack.com/services/...).
func NewSlackNotifier(url string) *SlackNotifier {
	return &SlackNotifier{
		URL:        url,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

// slackPayload mirrors the subset of Slack's incoming-webhook attachment
// format this notifier uses. See:
// https://api.slack.com/messaging/webhooks#legacy_message_formatting
type slackPayload struct {
	Attachments []slackAttachment `json:"attachments"`
}

type slackAttachment struct {
	Color string `json:"color"`
	Title string `json:"title"`
	Text  string `json:"text"`
}

func (s *SlackNotifier) Notify(findings []report.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	payload := slackPayload{Attachments: []slackAttachment{{
		Color: slackColor(maxSeverity(findings)),
		Title: fmt.Sprintf("vpsguard monitor detected %d change(s)", len(findings)),
		Text:  findingsList(findings),
	}}}

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("encoding Slack payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, s.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building Slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := s.httpClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending Slack notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("Slack webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// slackColor maps a severity to Slack's attachment color field, which
// accepts either a hex string or one of a few named values.
func slackColor(sev report.Severity) string {
	switch sev {
	case report.CRIT:
		return "danger"
	case report.WARN:
		return "warning"
	default:
		return "good"
	}
}
