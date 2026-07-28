package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/salamancacm/vpsguard/internal/report"
)

// telegramMaxMessageLen is the Bot API's hard limit on a sendMessage text
// body. See: https://core.telegram.org/bots/api#sendmessage
const telegramMaxMessageLen = 4096

// TelegramNotifier posts findings to a chat via the Telegram Bot API.
// Unlike Slack/Discord (a webhook URL), this requires a bot token and the
// target chat ID — there's no generic-webhook shortcut for Telegram.
type TelegramNotifier struct {
	BotToken string
	ChatID   string

	httpClient *http.Client

	// apiBase is overridable in tests; defaults to Telegram's real API.
	apiBase string
}

// NewTelegramNotifier returns a TelegramNotifier that sends messages as
// botToken to chatID (a user, group, or channel ID — see
// https://core.telegram.org/bots/api#sendmessage).
func NewTelegramNotifier(botToken, chatID string) *TelegramNotifier {
	return &TelegramNotifier{
		BotToken:   botToken,
		ChatID:     chatID,
		httpClient: &http.Client{Timeout: 10 * time.Second},
		apiBase:    "https://api.telegram.org",
	}
}

func (t *TelegramNotifier) Notify(findings []report.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	text := truncateForTelegram(formatMessage(findings))
	body, err := json.Marshal(map[string]string{
		"chat_id": t.ChatID,
		"text":    text,
	})
	if err != nil {
		return fmt.Errorf("encoding Telegram payload: %w", err)
	}

	apiBase := t.apiBase
	if apiBase == "" {
		apiBase = "https://api.telegram.org"
	}
	url := fmt.Sprintf("%s/bot%s/sendMessage", apiBase, t.BotToken)

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building Telegram request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := t.httpClient
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}

	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("sending Telegram notification: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("Telegram API returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// truncateForTelegram trims text to the Bot API's message length limit,
// leaving room for a note so a long finding list fails loudly (a shortened
// message) rather than the request silently getting rejected outright.
func truncateForTelegram(text string) string {
	if len(text) <= telegramMaxMessageLen {
		return text
	}
	const suffix = "\n... (truncated)"
	return text[:telegramMaxMessageLen-len(suffix)] + suffix
}
