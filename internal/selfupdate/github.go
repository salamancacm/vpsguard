package selfupdate

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// apiURL and downloadBaseURL can be overridden via environment variables
// for testing against a local mirror — the same pattern install.sh uses
// (VPSGUARD_INSTALL_BASE_URL). Checksum verification in Apply() is never
// skipped regardless of these, so pointing at an untrusted mirror can at
// worst make `update` fail closed, not install something unverified.
var (
	apiURL          = envOr("VPSGUARD_UPDATE_API_URL", "https://api.github.com/repos/salamancacm/vpsguard/releases/latest")
	downloadBaseURL = envOr("VPSGUARD_UPDATE_BASE_URL", "https://github.com/salamancacm/vpsguard/releases/latest/download")
)

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

type releaseInfo struct {
	TagName string `json:"tag_name"`
}

// LatestTag fetches the tag name (e.g. "v0.3.0") of the latest GitHub
// release via the API — unlike install.sh, which only needs to download
// an asset (and can use the /releases/latest/download/ redirect for
// that), `update` needs the actual version string to compare against and
// report, which the redirect endpoint alone doesn't expose.
func LatestTag() (string, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(apiURL)
	if err != nil {
		return "", fmt.Errorf("checking latest release: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("checking latest release: GitHub API returned HTTP %d", resp.StatusCode)
	}

	var info releaseInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return "", fmt.Errorf("parsing latest release response: %w", err)
	}
	if info.TagName == "" {
		return "", fmt.Errorf("latest release response had no tag_name")
	}
	return info.TagName, nil
}
