//go:build darwin

package updater

// macAsset is the universal disk image published for macOS.
const macAsset = "SyslogStudio-macos-universal.dmg"

// platformAssets are the assets target can pick on macOS.
func platformAssets() []string { return []string{macAsset} }

// target on macOS always uses the browser path: the .app is not code-signed or
// notarized, so a self-replace would be blocked by Gatekeeper. The user
// downloads the DMG and drags the app to /Applications.
func target() (string, applyMode) {
	return macAsset, applyBrowser
}
