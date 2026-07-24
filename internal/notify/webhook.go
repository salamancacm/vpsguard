package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/salamancacm/vpsguard/internal/report"
)

// WebhookNotifier POSTs a JSON summary of findings to a configured URL.
// The payload includes both "text" (Slack/Mattermost's field name) and
// "content" (Discord's field name) with the same message, so one webhook
// URL works across all three without per-provider configuration — each
// platform ignores the field it doesn't recognize.
type WebhookNotifier struct {
	URL string

	// httpClient is overridable in tests; defaults to a client with a
	// sane timeout so a hung webhook endpoint can't block `monitor`.
	httpClient *http.Client
}

// NewWebhookNotifier returns a WebhookNotifier posting to url.
func NewWebhookNotifier(url string) *WebhookNotifier {
	return &WebhookNotifier{
		URL:        url,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
}

func (w *WebhookNotifier) Notify(findings []report.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	text := formatMessage(findings)
	body, err := json.Marshal(map[string]string{
		"text":    text,
		"content": text,
	})
	if err != nil {
		return fmt.Errorf("encoding webhook payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := w.httpClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending webhook: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func formatMessage(findings []report.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, "vpsguard monitor detected %d change(s):\n", len(findings))
	for _, f := range findings {
		fmt.Fprintf(&b, "[%s] [%s] %s\n", f.Severity, f.Check, f.Message)
	}
	return b.String()
}
