package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"SyslogStudio/internal/updater"
)

const manifestName = "SyslogStudio-checksums.txt"

// verify judges a directory of release assets as the in-app updater will,
// before they are published: the manifest's signature against the public key
// embedded in internal/updater, its version line against tag, one entry for
// each file of the release and for each asset the updater downloads, and every
// file's SHA-256. A release it refuses is one every installed copy would
// refuse, so the release workflow stops there instead of publishing it.
func verify(dir, tag string) {
	n, err := verifyRelease(dir, tag)
	if err != nil {
		fatal("%s is not what the updater accepts: %v", tag, err)
	}
	fmt.Fprintf(os.Stderr, "updatersign: %s is what the updater accepts: signature, version line, %d assets\n", tag, n)
}

func verifyRelease(dir, tag string) (int, error) {
	manifest, err := os.ReadFile(filepath.Join(dir, manifestName))
	if err != nil {
		return 0, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, manifestName+".sig"))
	if err != nil {
		return 0, fmt.Errorf("the manifest is not signed: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	// What the updater downloads, then whatever else the release carries.
	assets := slices.Clone(updater.UpdateAssets)
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || name == manifestName || name == manifestName+".sig" || slices.Contains(assets, name) {
			continue
		}
		assets = append(assets, name)
	}

	sums, err := updater.AcceptManifest(manifest, sig, tag, assets)
	if err != nil {
		return 0, err
	}
	if listed := manifestEntries(manifest); listed != len(assets) {
		return 0, fmt.Errorf("the manifest lists %d files, the release has %d", listed, len(assets))
	}
	for _, asset := range assets {
		got, err := sha256File(filepath.Join(dir, asset))
		if errors.Is(err, fs.ErrNotExist) {
			return 0, fmt.Errorf("%s is listed but missing from the release", asset)
		}
		if err != nil {
			return 0, err
		}
		if !strings.EqualFold(got, sums[asset]) {
			return 0, fmt.Errorf("%s: SHA-256 %s, the manifest says %s", asset, got, sums[asset])
		}
	}
	return len(assets), nil
}

// manifestEntries counts the checksum lines, read as the updater reads them.
func manifestEntries(manifest []byte) int {
	n := 0
	for _, line := range strings.Split(string(manifest), "\n") {
		if f := strings.Fields(line); len(f) == 2 && f[0] != "version" {
			n++
		}
	}
	return n
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
