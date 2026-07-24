package harden

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBackupFile_CopiesContent(t *testing.T) {
	path := writeTempFile(t, "PermitRootLogin no\n")

	backupPath, err := BackupFile(path)
	if err != nil {
		t.Fatalf("BackupFile() error: %v", err)
	}
	if backupPath == "" {
		t.Fatal("BackupFile() returned an empty path for an existing file")
	}

	got := readFile(t, backupPath)
	if got != "PermitRootLogin no\n" {
		t.Errorf("backup content = %q, want the original file's content", got)
	}

	// The original must be untouched by backing it up.
	if got := readFile(t, path); got != "PermitRootLogin no\n" {
		t.Errorf("BackupFile() modified the original: %q", got)
	}
}

func TestBackupFile_MissingSourceIsNotAnError(t *testing.T) {
	// SSH's harden.SSH relies on this: a file that doesn't exist yet isn't
	// a failure, it just means there's nothing to back up.
	backupPath, err := BackupFile(filepath.Join(t.TempDir(), "does-not-exist"))
	if err != nil {
		t.Fatalf("BackupFile() on a missing source returned an error: %v", err)
	}
	if backupPath != "" {
		t.Errorf("BackupFile() on a missing source returned %q, want empty", backupPath)
	}
}

func TestBackupFile_NameIncludesOriginalPath(t *testing.T) {
	path := writeTempFile(t, "data")

	backupPath, err := BackupFile(path)
	if err != nil {
		t.Fatalf("BackupFile() error: %v", err)
	}

	dir := filepath.Dir(backupPath)
	if dir != filepath.Dir(path) {
		t.Errorf("backup dir = %q, want same directory as original (%q)", dir, filepath.Dir(path))
	}
	base := filepath.Base(backupPath)
	wantPrefix := filepath.Base(path) + ".bak."
	if len(base) <= len(wantPrefix) || base[:len(wantPrefix)] != wantPrefix {
		t.Errorf("backup filename %q doesn't start with %q", base, wantPrefix)
	}
	if _, err := os.Stat(backupPath); err != nil {
		t.Errorf("backup file doesn't exist on disk: %v", err)
	}
}
