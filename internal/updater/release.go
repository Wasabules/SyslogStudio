package updater

import "fmt"

// UpdateAssets are the release assets the updater downloads (target in
// apply_*.go picks one per system and kind of installation), by the fixed
// names the release workflow publishes. A release missing one leaves the
// copies that would fetch it without their update.
var UpdateAssets = []string{
	"SyslogStudio-windows-amd64.exe",
	"SyslogStudio-windows-amd64-setup.exe",
	"SyslogStudio-linux-amd64",
	"SyslogStudio-linux-amd64.deb",
	"SyslogStudio-macos-universal.dmg",
}

// AcceptManifest is the updater's own judgement of a release's checksums
// manifest, without the network: the signature against the public key this
// build embeds, the version line against tag, and exactly one entry for each
// of assets. It returns the SHA-256 the updater would require of each asset.
//
// The release workflow runs it on the signed manifest before publishing
// (tools/updatersign verify), so a release that installed copies would refuse
// is never published.
func AcceptManifest(manifest, sig []byte, tag string, assets []string) (map[string]string, error) {
	if err := acceptManifest(manifest, sig, tag); err != nil {
		return nil, err
	}
	sums := make(map[string]string, len(assets))
	for _, asset := range assets {
		sum, err := parseChecksum(manifest, asset)
		if err != nil {
			return nil, err
		}
		sums[asset] = sum
	}
	return sums, nil
}

// acceptManifest is what every update checks before trusting a manifest: its
// mandatory signature, then its version line, which binds it to the release
// being installed and so defeats the replay of an older, validly signed
// manifest by a compromised CDN.
func acceptManifest(manifest, sig []byte, expectedVersion string) error {
	if err := verifyManifestSignature(manifest, sig); err != nil {
		return err
	}
	mv := parseManifestVersion(manifest)
	if mv == "" {
		return fmt.Errorf("checksums manifest is missing a version line")
	}
	if normalizeVersion(mv) != normalizeVersion(expectedVersion) {
		return fmt.Errorf("checksums manifest version %q does not match the expected release %q", mv, expectedVersion)
	}
	return nil
}
