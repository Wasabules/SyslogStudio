package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"slices"
	"strings"
	"testing"
)

// The list the release is checked against holds what this system's updater
// downloads: run on Windows, Linux and macOS, CI covers all three.
func TestUpdateAssets_HoldWhatThisSystemDownloads(t *testing.T) {
	for _, asset := range platformAssets() {
		if !slices.Contains(UpdateAssets, asset) {
			t.Errorf("%s is downloaded by the updater but missing from UpdateAssets", asset)
		}
	}
}

// signWith makes the test key the embedded one for the length of the test and
// returns a signer for manifests.
func signWith(t *testing.T) func(manifest string) []byte {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := updaterPublicKey
	updaterPublicKey = base64.StdEncoding.EncodeToString(pub)
	t.Cleanup(func() { updaterPublicKey = old })
	return func(manifest string) []byte {
		return []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(manifest))))
	}
}

func TestAcceptManifest(t *testing.T) {
	sign := signWith(t)
	manifest := strings.Join([]string{
		"version v1.12.0",
		"aaa  SyslogStudio-windows-amd64.exe",
		"bbb  SyslogStudio-linux-amd64",
		"",
	}, "\n")
	assets := []string{"SyslogStudio-windows-amd64.exe", "SyslogStudio-linux-amd64"}

	sums, err := AcceptManifest([]byte(manifest), sign(manifest), "v1.12.0", assets)
	if err != nil {
		t.Fatalf("a good manifest was refused: %v", err)
	}
	if sums["SyslogStudio-windows-amd64.exe"] != "aaa" || sums["SyslogStudio-linux-amd64"] != "bbb" {
		t.Errorf("sums = %v", sums)
	}
	// The tag may come with or without its v, as the updater compares them.
	if _, err := AcceptManifest([]byte(manifest), sign(manifest), "1.12.0", assets); err != nil {
		t.Errorf("tag without v refused: %v", err)
	}

	if _, err := AcceptManifest([]byte(manifest), sign(manifest), "v1.11.1", assets); err == nil {
		t.Error("another release's tag was accepted")
	}

	// Last, since it changes the embedded key: a release signed by a key the
	// app does not carry, as after a rotation that missed verify.go.
	signWith(t)
	if _, err := AcceptManifest([]byte(manifest), sign(manifest), "v1.12.0", assets); err == nil {
		t.Error("a signature by another key was accepted")
	}
}

func TestAcceptManifest_RefusesWhatTheUpdaterRefuses(t *testing.T) {
	sign := signWith(t)
	assets := []string{"SyslogStudio-linux-amd64"}
	for name, manifest := range map[string]string{
		"no version line":  "bbb  SyslogStudio-linux-amd64\n",
		"an asset missing": "version v1.12.0\naaa  SyslogStudio-windows-amd64.exe\n",
		"an asset twice":   "version v1.12.0\nbbb  SyslogStudio-linux-amd64\nccc  SyslogStudio-linux-amd64\n",
	} {
		if _, err := AcceptManifest([]byte(manifest), sign(manifest), "v1.12.0", assets); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	manifest := "version v1.12.0\nbbb  SyslogStudio-linux-amd64\n"
	if _, err := AcceptManifest([]byte(manifest+"ddd  extra\n"), sign(manifest), "v1.12.0", assets); err == nil {
		t.Error("a manifest changed after signing was accepted")
	}
}
