package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/minio/selfupdate"
	wruntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

const progressEvent = "update:progress"

// cleanupLeftoverOld removes a stale ".old" binary left by a previous Windows
// self-replace: minio/selfupdate renames the running exe aside and cannot
// delete it until the process exits, so it lingers until the next launch.
func cleanupLeftoverOld() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	dir, base := filepath.Split(exe)
	_ = os.Remove(exe + ".old")
	_ = os.Remove(filepath.Join(dir, "."+base+".old"))
}

// DownloadAndApply downloads the pending update, verifies its checksum (and,
// when enforced, the manifest signature), and applies it according to the
// resolved mode. Requires a prior successful CheckForUpdate.
func (s *Service) DownloadAndApply() error {
	if !s.applyMu.TryLock() {
		return fmt.Errorf("an update is already being downloaded and applied")
	}
	defer s.applyMu.Unlock()

	s.mu.Lock()
	p := s.pending
	ctx := s.ctx
	s.mu.Unlock()
	if p == nil {
		return fmt.Errorf("no pending update; check for updates first")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	if p.mode == applyBrowser {
		wruntime.BrowserOpenURL(ctx, p.assetURL)
		return nil
	}

	// Downgrade guard: never self-apply a version that is not strictly newer.
	if !isNewer(AppVersion, p.version) {
		return fmt.Errorf("refusing update: %s is not newer than the running %s",
			displayVersion(p.version), displayVersion(AppVersion))
	}

	if p.checksumURL == "" {
		return fmt.Errorf("release is missing the checksums manifest; cannot verify the update")
	}
	wantSum, err := s.verifiedChecksum(ctx, p.checksumURL, p.checksumSigURL, p.assetName, p.version)
	if err != nil {
		return err
	}

	tmpPath, gotSum, err := s.download(ctx, p.assetURL, p.assetName, p.size)
	if err != nil {
		return err
	}
	defer os.Remove(tmpPath)

	if !strings.EqualFold(gotSum, wantSum) {
		return fmt.Errorf("checksum mismatch for %s: expected %s, got %s", p.assetName, wantSum, gotSum)
	}

	switch p.mode {
	case applyInstaller:
		return s.runInstaller(ctx, tmpPath)
	default:
		return s.applyBinary(ctx, tmpPath)
	}
}

// verifiedChecksum fetches the checksums manifest, verifies its mandatory
// Ed25519 signature and that it is bound to expectedVersion, and returns the
// expected SHA-256 for asset.
func (s *Service) verifiedChecksum(ctx context.Context, checksumURL, sigURL, asset, expectedVersion string) (string, error) {
	manifest, err := s.fetchBytes(ctx, checksumURL)
	if err != nil {
		return "", fmt.Errorf("fetch checksums: %w", err)
	}
	if sigURL == "" {
		return "", fmt.Errorf("release checksums are not signed")
	}
	sig, err := s.fetchBytes(ctx, sigURL)
	if err != nil {
		return "", fmt.Errorf("fetch checksums signature: %w", err)
	}
	if err := verifyManifestSignature(manifest, sig); err != nil {
		return "", err
	}
	// Bind the signed manifest to the release we intend to install, defeating a
	// replay of an old but validly-signed manifest served by a compromised CDN.
	mv := parseManifestVersion(manifest)
	if mv == "" {
		return "", fmt.Errorf("checksums manifest is missing a version line")
	}
	if normalizeVersion(mv) != normalizeVersion(expectedVersion) {
		return "", fmt.Errorf("checksums manifest version %q does not match the expected release %q", mv, expectedVersion)
	}
	return parseChecksum(manifest, asset)
}

// download streams the asset to a temp file, returning its path and the
// hex SHA-256 computed on the fly. It emits progress events while downloading.
func (s *Service) download(ctx context.Context, url, asset string, size int64) (path, sum string, err error) {
	// Generous deadline: large installers on slow links must succeed, but a
	// stalled connection must not hang forever (the client has no global timeout).
	ctx, cancel := context.WithTimeout(ctx, 20*time.Minute)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("download: unexpected status %d", resp.StatusCode)
	}

	f, err := os.CreateTemp("", "syslogstudio-update-*-"+asset)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	// Bound the read to the authenticated asset size (plus small slack) so a
	// compromised CDN cannot stream unbounded data into the temp dir; if it
	// serves more, the truncated bytes fail the checksum and the update aborts.
	var body io.Reader = resp.Body
	if size > 0 {
		body = io.LimitReader(resp.Body, size+1024)
	}
	h := sha256.New()
	pr := &progressReader{ctx: ctx, reader: body, total: resp.ContentLength}
	if _, err := io.Copy(io.MultiWriter(f, h), pr); err != nil {
		os.Remove(f.Name())
		return "", "", err
	}
	wruntime.EventsEmit(ctx, progressEvent, 100)
	return f.Name(), hex.EncodeToString(h.Sum(nil)), nil
}

// fetchBytes downloads a small file (checksums/signature) fully into memory,
// capped at 1 MiB.
func (s *Service) fetchBytes(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// parseChecksum finds asset's SHA-256 in a `sha256sum`-format manifest
// ("<hex>␠␠<name>" per line), tolerating the "*" binary-mode marker. It matches
// the manifest name exactly (the manifest uses bare asset names) and rejects
// duplicate entries so a malicious manifest can't smuggle a second line.
func parseChecksum(manifest []byte, asset string) (string, error) {
	var sum string
	matches := 0
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) != 2 || fields[0] == "version" {
			continue
		}
		name := strings.TrimPrefix(fields[1], "*")
		if name == asset {
			sum = fields[0]
			matches++
		}
	}
	if matches == 0 {
		return "", fmt.Errorf("no checksum for %q in manifest", asset)
	}
	if matches > 1 {
		return "", fmt.Errorf("duplicate checksum entries for %q in manifest", asset)
	}
	return sum, nil
}

// parseManifestVersion extracts the "version <tag>" line the release workflow
// prepends to the signed checksums manifest, or "" if absent.
func parseManifestVersion(manifest []byte) string {
	for _, line := range strings.Split(string(manifest), "\n") {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 2 && fields[0] == "version" {
			return fields[1]
		}
	}
	return ""
}

// applyBinary self-replaces the running executable with the downloaded binary
// and relaunches.
func (s *Service) applyBinary(ctx context.Context, path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := selfupdate.Apply(f, selfupdate.Options{}); err != nil {
		if rerr := selfupdate.RollbackError(err); rerr != nil {
			return fmt.Errorf("update failed and rollback failed: %v (rollback: %v)", err, rerr)
		}
		return fmt.Errorf("applying update: %w", err)
	}
	s.relaunch(ctx)
	return nil
}

// runInstaller launches the downloaded installer and quits the app so the
// installer can replace files in place.
func (s *Service) runInstaller(ctx context.Context, path string) error {
	target := path
	if !strings.EqualFold(filepath.Ext(path), ".exe") {
		target = path + ".exe"
		if err := os.Rename(path, target); err != nil {
			return fmt.Errorf("prepare installer: %w", err)
		}
	}
	if err := exec.Command(target).Start(); err != nil {
		return fmt.Errorf("launch installer: %w", err)
	}
	wruntime.Quit(ctx)
	return nil
}

// relaunch starts a fresh copy of the (now updated) executable and quits.
func (s *Service) relaunch(ctx context.Context) {
	if exe, err := os.Executable(); err == nil {
		_ = exec.Command(exe).Start()
	}
	time.Sleep(300 * time.Millisecond)
	wruntime.Quit(ctx)
}

// progressReader wraps the download body and emits throttled integer-percent
// update:progress events.
type progressReader struct {
	ctx      context.Context
	reader   io.Reader
	total    int64
	read     int64
	lastPct  int
	lastEmit time.Time
}

func (pr *progressReader) Read(p []byte) (int, error) {
	n, err := pr.reader.Read(p)
	pr.read += int64(n)
	if pr.total > 0 {
		pct := int(pr.read * 100 / pr.total)
		if pct != pr.lastPct && time.Since(pr.lastEmit) > 100*time.Millisecond {
			pr.lastPct = pct
			pr.lastEmit = time.Now()
			wruntime.EventsEmit(pr.ctx, progressEvent, pct)
		}
	}
	return n, err
}
