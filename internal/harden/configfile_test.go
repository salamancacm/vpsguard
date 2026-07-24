package harden

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSetDirective_AppendsWhenMissing(t *testing.T) {
	path := writeTempFile(t, "Port 22\n")

	changed, err := SetDirective(path, "PermitRootLogin", "no")
	if err != nil {
		t.Fatalf("SetDirective() error: %v", err)
	}
	if !changed {
		t.Error("SetDirective() reported no change when the directive was missing")
	}

	got := readFile(t, path)
	want := "Port 22\nPermitRootLogin no\n"
	if got != want {
		t.Errorf("file content = %q, want %q", got, want)
	}
}

func TestSetDirective_ReplacesExistingValue(t *testing.T) {
	path := writeTempFile(t, "PermitRootLogin yes\nPort 22\n")

	changed, err := SetDirective(path, "PermitRootLogin", "no")
	if err != nil {
		t.Fatalf("SetDirective() error: %v", err)
	}
	if !changed {
		t.Error("SetDirective() reported no change when the value needed updating")
	}

	got := readFile(t, path)
	want := "PermitRootLogin no\nPort 22\n"
	if got != want {
		t.Errorf("file content = %q, want %q", got, want)
	}
}

func TestSetDirective_UncommentsAndSetsValue(t *testing.T) {
	path := writeTempFile(t, "#PermitRootLogin prohibit-password\n")

	changed, err := SetDirective(path, "PermitRootLogin", "no")
	if err != nil {
		t.Fatalf("SetDirective() error: %v", err)
	}
	if !changed {
		t.Error("SetDirective() reported no change for a commented-out directive")
	}

	got := readFile(t, path)
	want := "PermitRootLogin no\n"
	if got != want {
		t.Errorf("file content = %q, want %q", got, want)
	}
}

func TestSetDirective_IdempotentWhenAlreadyCorrect(t *testing.T) {
	path := writeTempFile(t, "PermitRootLogin no\n")

	changed, err := SetDirective(path, "PermitRootLogin", "no")
	if err != nil {
		t.Fatalf("SetDirective() error: %v", err)
	}
	if changed {
		t.Error("SetDirective() reported a change when the value was already correct — must be idempotent")
	}
}

func TestSetDirective_CaseInsensitiveKeyMatch(t *testing.T) {
	path := writeTempFile(t, "permitrootlogin yes\n")

	changed, err := SetDirective(path, "PermitRootLogin", "no")
	if err != nil {
		t.Fatalf("SetDirective() error: %v", err)
	}
	if !changed {
		t.Error("SetDirective() should match the key case-insensitively (sshd_config semantics)")
	}
	got := readFile(t, path)
	if got != "PermitRootLogin no\n" {
		t.Errorf("file content = %q", got)
	}
}

func TestSetDirective_MissingFileIsAnError(t *testing.T) {
	if _, err := SetDirective(filepath.Join(t.TempDir(), "nope"), "Port", "22"); err == nil {
		t.Error("SetDirective() on a missing file should return an error, not silently succeed")
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "sshd_config")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("writing test fixture: %v", err)
	}
	return path
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}
	return string(data)
}
