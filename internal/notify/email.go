package notify

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/salamancacm/vpsguard/internal/report"
)

// EmailNotifier shells out to whatever local mail transport is already
// configured (sendmail or mailutils' `mail`), rather than embedding an
// SMTP client — VPS often already have one of these set up for other
// purposes (cron job output, other tools), and this avoids vpsguard
// needing to know SMTP credentials at all.
type EmailNotifier struct {
	To string
}

func NewEmailNotifier(to string) *EmailNotifier {
	return &EmailNotifier{To: to}
}

func (e *EmailNotifier) Notify(findings []report.Finding) error {
	if len(findings) == 0 {
		return nil
	}

	body := formatMessage(findings)
	subject := fmt.Sprintf("vpsguard monitor: %d change(s) detected", len(findings))

	switch {
	case commandExists("sendmail"):
		return e.sendViaSendmail(subject, body)
	case commandExists("mail"):
		return e.sendViaMail(subject, body)
	default:
		return fmt.Errorf("no local mail transport found (checked for 'sendmail' and 'mail') — install one, or configure webhook_url instead")
	}
}

func (e *EmailNotifier) sendViaSendmail(subject, body string) error {
	msg := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\n%s\r\n", e.To, subject, body)
	cmd := exec.Command("sendmail", "-t")
	cmd.Stdin = strings.NewReader(msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("sendmail failed: %w (%s)", err, out)
	}
	return nil
}

func (e *EmailNotifier) sendViaMail(subject, body string) error {
	cmd := exec.Command("mail", "-s", subject, e.To)
	cmd.Stdin = strings.NewReader(body)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("mail failed: %w (%s)", err, out)
	}
	return nil
}

func commandExists(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}
