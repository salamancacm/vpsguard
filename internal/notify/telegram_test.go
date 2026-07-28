package notify

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/salamancacm/vpsguard/internal/report"
)

func TestTruncateForTelegram(t *testing.T) {
	short := "well within the limit"
	if got := truncateForTelegram(short); got != short {
		t.Errorf("truncateForTelegram(short) = %q, want unchanged", got)
	}

	long := strings.Repeat("x", telegramMaxMessageLen+500)
	got := truncateForTelegram(long)
	if len(got) != telegramMaxMessageLen {
		t.Errorf("truncateForTelegram(long) length = %d, want %d", len(got), telegramMaxMessageLen)
	}
	if !strings.HasSuffix(got, "(truncated)") {
		t.Errorf("truncateForTelegram(long) = %q, want it to end with a truncation note", got)
	}
}

func TestTelegramNotifier_Notify(t *testing.T) {
	var gotPath string
	var gotBody map[string]string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &gotBody)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	n := NewTelegramNotifier("123:ABC", "-100999")
	n.apiBase = server.URL
	n.httpClient = server.Client()

	findings := []report.Finding{report.NewFinding("ssh", report.CRIT, "root login enabled", "", false)}
	if err := n.Notify(findings); err != nil {
		t.Fatalf("Notify() returned error: %v", err)
	}

	if gotPath != "/bot123:ABC/sendMessage" {
		t.Errorf("request path = %q, want %q", gotPath, "/bot123:ABC/sendMessage")
	}
	if gotBody["chat_id"] != "-100999" {
		t.Errorf("chat_id = %q, want %q", gotBody["chat_id"], "-100999")
	}
	if !strings.Contains(gotBody["text"], "root login enabled") {
		t.Errorf("text = %q, missing finding message", gotBody["text"])
	}
}

func TestTelegramNotifier_Notify_EmptyFindingsSendsNothing(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer server.Close()

	n := NewTelegramNotifier("123:ABC", "-100999")
	n.apiBase = server.URL
	n.httpClient = server.Client()

	if err := n.Notify(nil); err != nil {
		t.Fatalf("Notify(nil) returned error: %v", err)
	}
	if called {
		t.Error("Notify(nil) should not make an HTTP request")
	}
}

func TestTelegramNotifier_Notify_HTTPErrorPropagates(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer server.Close()

	n := NewTelegramNotifier("bad-token", "-100999")
	n.apiBase = server.URL
	n.httpClient = server.Client()

	findings := []report.Finding{report.NewFinding("ssh", report.CRIT, "x", "", false)}
	if err := n.Notify(findings); err == nil {
		t.Error("Notify() with a 403 response should return an error")
	}
}
