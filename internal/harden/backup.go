package harden

import (
	"fmt"
	"io"
	"os"
	"time"
)

// BackupFile copies path to path.bak.<unix-timestamp> before it gets
// modified, so a bad edit can always be reverted by hand. Returns the
// backup path, or "" if the source file doesn't exist yet.
func BackupFile(path string) (string, error) {
	src, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	defer src.Close()

	backupPath := fmt.Sprintf("%s.bak.%d", path, time.Now().Unix())
	dst, err := os.OpenFile(backupPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", err
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", err
	}
	return backupPath, nil
}
