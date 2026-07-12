package updater

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	apiBase = "https://api.github.com"

	// checksumsAsset is the release asset that lists the SHA-256 of every
	// other asset; checksumsAsset+".sig" is its Ed25519 signature.
	checksumsAsset = "SyslogStudio-checksums.txt"
)

type ghAsset struct {
	Name string `json:"name"`
	URL  string `json:"browser_download_url"`
	Size int64  `json:"size"`
}

type ghRelease struct {
	TagName     string    `json:"tag_name"`
	Name        string    `json:"name"`
	Body        string    `json:"body"`
	HTMLURL     string    `json:"html_url"`
	PublishedAt time.Time `json:"published_at"`
	Prerelease  bool      `json:"prerelease"`
	Draft       bool      `json:"draft"`
	Assets      []ghAsset `json:"assets"`
}

// assetURL returns the download URL of the named asset, or "" if absent.
func (r *ghRelease) assetURL(name string) string {
	for _, a := range r.Assets {
		if a.Name == name {
			return a.URL
		}
	}
	return ""
}

// latestRelease fetches the repository's latest (non-draft) release.
func (s *Service) latestRelease(ctx context.Context) (*ghRelease, error) {
	url := fmt.Sprintf("%s/repos/%s/%s/releases/latest", apiBase, s.owner, s.repo)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "SyslogStudio-updater")

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Drain a little for connection reuse, then report.
		_, _ = io.CopyN(io.Discard, resp.Body, 512)
		return nil, fmt.Errorf("github: unexpected status %d", resp.StatusCode)
	}

	var rel ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&rel); err != nil {
		return nil, fmt.Errorf("decode release: %w", err)
	}
	return &rel, nil
}
