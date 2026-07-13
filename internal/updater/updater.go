// Package updater implements SyslogStudio's assisted in-app auto-update,
// backed by GitHub Releases. It checks the latest release, compares versions
// with semver, downloads the platform asset, verifies it against a SHA-256
// manifest (optionally Ed25519-signed), and applies it — self-replacing the
// binary, running the installer, or opening the browser depending on how the
// app was installed.
package updater

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/mod/semver"

	"SyslogStudio/internal/models"
)

// applyMode describes how a resolved update is applied on this platform.
type applyMode int

const (
	applyReplace   applyMode = iota // self-replace the binary, then relaunch
	applyInstaller                  // download & run the installer, then quit
	applyBrowser                    // open the release/asset URL in a browser
)

// pending caches the resolved download between CheckForUpdate and
// DownloadAndApply.
type pending struct {
	version        string
	assetURL       string
	assetName      string
	size           int64 // authenticated asset size from the GitHub API (0 if unknown)
	checksumURL    string
	checksumSigURL string
	mode           applyMode
}

// Service checks GitHub Releases and applies updates for one repository.
type Service struct {
	owner string
	repo  string
	// client is host-pinned to GitHub for the API/manifest/signature requests.
	client *http.Client
	// dlClient downloads the release asset. Its redirects are only required to
	// stay on HTTPS, not on a GitHub host: GitHub has changed its asset CDN
	// before, and integrity is already guaranteed by the signed-manifest
	// checksum, so pinning the host here would only add an availability
	// failure mode without adding security.
	dlClient *http.Client

	mu      sync.Mutex
	ctx     context.Context
	pending *pending
	applyMu sync.Mutex // serializes DownloadAndApply; rejects concurrent applies
}

// NewService creates an updater for the given GitHub owner/repo.
func NewService(owner, repo string) *Service {
	return &Service{
		owner:    owner,
		repo:     repo,
		client:   newHTTPClient(true),
		dlClient: newHTTPClient(false),
	}
}

// newHTTPClient builds an HTTP client for update traffic. It has no global
// timeout — the asset download can be large and slow, so each request is bounded
// by its own context deadline instead. Redirects are always constrained to
// HTTPS so a hostile redirect cannot downgrade to plaintext. When pinHost is
// true the redirect target must also be a GitHub host (for the API, manifest,
// and signature); the asset download uses pinHost=false (see Service.dlClient).
func newHTTPClient(pinHost bool) *http.Client {
	return &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("stopped after 10 redirects")
			}
			if req.URL.Scheme != "https" {
				return fmt.Errorf("refusing non-https redirect to %s", req.URL.Hostname())
			}
			if pinHost && !isGitHubHost(req.URL.Hostname()) {
				return fmt.Errorf("refusing redirect to %s://%s", req.URL.Scheme, req.URL.Hostname())
			}
			return nil
		},
	}
}

func isGitHubHost(host string) bool {
	host = strings.ToLower(host)
	return host == "github.com" ||
		strings.HasSuffix(host, ".github.com") ||
		strings.HasSuffix(host, ".githubusercontent.com")
}

// SetContext gives the updater the Wails runtime context, used for progress
// events, opening the browser, and quitting. Called from App.startup.
func (s *Service) SetContext(ctx context.Context) {
	s.mu.Lock()
	s.ctx = ctx
	s.mu.Unlock()
	cleanupLeftoverOld()
}

func (s *Service) context() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ctx != nil {
		return s.ctx
	}
	return context.Background()
}

// CheckForUpdate queries the latest release and returns update info. Dev builds
// short-circuit with no update. On error the returned info still carries
// CurrentVersion so the UI can display it.
func (s *Service) CheckForUpdate() (models.UpdateInfo, error) {
	info := models.UpdateInfo{CurrentVersion: displayVersion(AppVersion)}
	if isDevVersion() {
		return info, nil
	}
	// Authenticity is mandatory: without an embedded signing key, updates are
	// disabled entirely rather than silently downgraded to SHA-256-only.
	if !signatureEnforced() {
		return info, fmt.Errorf("auto-update is disabled: no updater signing key is configured")
	}

	ctx, cancel := context.WithTimeout(s.context(), 15*time.Second)
	defer cancel()

	rel, err := s.latestRelease(ctx)
	if err != nil {
		return info, err
	}
	if rel.Draft || rel.Prerelease {
		return info, nil
	}

	info.LatestVersion = displayVersion(rel.TagName)
	info.ReleaseNotes = rel.Body
	info.ReleaseURL = rel.HTMLURL
	info.UpdateURL = rel.HTMLURL
	if !rel.PublishedAt.IsZero() {
		info.PublishedAt = rel.PublishedAt.Format(time.RFC3339)
	}

	if !isNewer(AppVersion, rel.TagName) {
		return info, nil
	}
	info.HasUpdate = true

	assetName, mode := target()
	assetURL := rel.assetURL(assetName)
	if assetURL == "" {
		// No self-update asset for this platform in this release.
		mode = applyBrowser
	}
	// Self-apply needs the signed checksums manifest AND its signature. If the
	// release lacks either (e.g. a hand-made release), don't advertise a
	// self-apply that would only fail at download time — offer the manual path.
	if mode != applyBrowser &&
		(rel.assetURL(checksumsAsset) == "" || rel.assetURL(checksumsAsset+".sig") == "") {
		mode = applyBrowser
	}
	if mode == applyBrowser {
		// Open the release page (where the signed checksums are visible)
		// rather than a direct, unverified asset link.
		assetURL = rel.HTMLURL
	}
	info.AssetName = assetName
	info.AssetURL = assetURL
	info.CanSelfApply = mode != applyBrowser

	s.mu.Lock()
	s.pending = &pending{
		version:        rel.TagName,
		assetURL:       assetURL,
		assetName:      assetName,
		size:           rel.assetSize(assetName),
		checksumURL:    rel.assetURL(checksumsAsset),
		checksumSigURL: rel.assetURL(checksumsAsset + ".sig"),
		mode:           mode,
	}
	s.mu.Unlock()

	return info, nil
}

// isNewer reports whether latest > current, compared as semver. Non-semver
// tags on either side yield false (no update), which is the safe default.
func isNewer(current, latest string) bool {
	c := normalizeVersion(current)
	l := normalizeVersion(latest)
	if !semver.IsValid(c) || !semver.IsValid(l) {
		return false
	}
	return semver.Compare(l, c) > 0
}

// normalizeVersion forces a leading "v", which golang.org/x/mod/semver requires.
func normalizeVersion(v string) string {
	if v == "" || v[0] == 'v' {
		return v
	}
	return "v" + v
}

// displayVersion strips a leading "v"/"V" for UI display.
func displayVersion(v string) string {
	if len(v) > 0 && (v[0] == 'v' || v[0] == 'V') {
		return v[1:]
	}
	return v
}
