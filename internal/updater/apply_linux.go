//go:build linux

package updater

import "os"

const (
	linuxDebAsset    = "SyslogStudio-linux-amd64.deb"
	linuxBinaryAsset = "SyslogStudio-linux-amd64"
	// debInstallPath is where the .deb package installs the binary
	// (see the release workflow's dpkg-deb step).
	debInstallPath = "/usr/bin/syslogstudio"
)

// target on Linux: a copy installed from the .deb hands the new .deb to the
// browser (dpkg needs root); a portable binary self-replaces.
func target() (string, applyMode) {
	if exe, err := os.Executable(); err == nil && exe == debInstallPath {
		return linuxDebAsset, applyBrowser
	}
	return linuxBinaryAsset, applyReplace
}
