package selfupdate

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Apply downloads the latest release's binary for the current platform,
// verifies it against the published checksums.txt, and atomically
// replaces the currently running executable. Only linux/amd64 and
// linux/arm64 are supported, matching what release.yml publishes.
//
// The replace is atomic on the same filesystem: the new binary is
// written alongside the target and then os.Rename'd over it, so a
// process that's currently executing the old binary keeps running fine
// (Linux keeps the old inode open until it exits) and there's never a
// moment where the target path is missing or half-written.
func Apply() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("self-update only supports linux (running on %s)", runtime.GOOS)
	}
	arch := runtime.GOARCH
	if arch != "amd64" && arch != "arm64" {
		return fmt.Errorf("no vpsguard release binary for architecture %s", arch)
	}
	assetName := "vpsguard-linux-" + arch

	binData, err := download(downloadBaseURL + "/" + assetName)
	if err != nil {
		return fmt.Errorf("downloading %s: %w", assetName, err)
	}
	checksumsData, err := download(downloadBaseURL + "/checksums.txt")
	if err != nil {
		return fmt.Errorf("downloading checksums.txt: %w", err)
	}

	expected, err := extractChecksum(string(checksumsData), assetName)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(binData)
	actual := hex.EncodeToString(sum[:])
	if actual != expected {
		return fmt.Errorf("checksum mismatch for %s (expected %s, got %s) — refusing to install", assetName, expected, actual)
	}

	exePath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("determining current executable path: %w", err)
	}
	exePath, err = filepath.EvalSymlinks(exePath)
	if err != nil {
		return fmt.Errorf("resolving executable path: %w", err)
	}

	tmpPath := fmt.Sprintf("%s.new.%d", exePath, time.Now().UnixNano())
	if err := os.WriteFile(tmpPath, binData, 0o755); err != nil {
		return fmt.Errorf("writing new binary: %w", err)
	}
	if err := os.Rename(tmpPath, exePath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("replacing %s: %w", exePath, err)
	}
	return nil
}

func download(url string) ([]byte, error) {
	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// extractChecksum finds the "<sha256>  <assetName>" line for assetName in
// a checksums.txt-formatted file (as produced by `sha256sum *`).
func extractChecksum(checksums, assetName string) (string, error) {
	for _, line := range strings.Split(checksums, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == assetName {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("no checksum entry found for %s", assetName)
}
