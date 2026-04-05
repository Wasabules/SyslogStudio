package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// AppVersion is the current application version. Set at build time via ldflags.
var AppVersion = "dev"

const (
	githubRepo      = "Wasabules/SyslogStudio"
	releaseCheckURL = "https://api.github.com/repos/" + githubRepo + "/releases/latest"
)

// UpdateInfo contains information about an available update.
type UpdateInfo struct {
	CurrentVersion string `json:"currentVersion"`
	LatestVersion  string `json:"latestVersion"`
	UpdateURL      string `json:"updateUrl"`
	HasUpdate      bool   `json:"hasUpdate"`
}

type githubRelease struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
}

// CheckForUpdate queries GitHub for the latest release.
func CheckForUpdate() UpdateInfo {
	info := UpdateInfo{
		CurrentVersion: AppVersion,
	}

	if AppVersion == "dev" {
		return info
	}

	client := http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(releaseCheckURL)
	if err != nil {
		slog.Debug("update check failed", "error", err)
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return info
	}

	var release githubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		slog.Debug("failed to parse release info", "error", err)
		return info
	}

	info.LatestVersion = release.TagName
	info.UpdateURL = release.HTMLURL
	info.HasUpdate = isNewer(release.TagName, AppVersion)

	if info.HasUpdate {
		slog.Info("update available", "current", AppVersion, "latest", release.TagName)
	}

	return info
}

// isNewer returns true if latest > current using simple string comparison on semver tags.
func isNewer(latest, current string) bool {
	latest = strings.TrimPrefix(latest, "v")
	current = strings.TrimPrefix(current, "v")
	if latest == "" || current == "" {
		return false
	}

	lParts := strings.Split(latest, ".")
	cParts := strings.Split(current, ".")

	for i := 0; i < len(lParts) && i < len(cParts); i++ {
		if lParts[i] > cParts[i] {
			return true
		}
		if lParts[i] < cParts[i] {
			return false
		}
	}
	return len(lParts) > len(cParts)
}

// GetAppVersion returns the current version string.
func GetAppVersion() string {
	return AppVersion
}

// OpenURL opens a URL in the default browser.
func OpenURL(url string) error {
	// This will be called via Wails, which handles it client-side
	return fmt.Errorf("use window.open() from frontend")
}
