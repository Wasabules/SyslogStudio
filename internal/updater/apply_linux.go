//go:build linux

package updater

import (
	"os"
	"path/filepath"
)

const (
	linuxDebAsset    = "SyslogStudio-linux-amd64.deb"
	linuxBinaryAsset = "SyslogStudio-linux-amd64"
	// debInstallPath is where the .deb package installs the binary
	// (see the release workflow's dpkg-deb step).
	debInstallPath = "/usr/bin/syslogstudio"
)

// target on Linux: a managed install (from the .deb, or any location the
// running user cannot replace in place — e.g. a root-owned /usr/bin) hands the
// new .deb to the browser; a portable binary the user owns self-replaces.
func target() (string, applyMode) {
	exe, err := os.Executable()
	if err != nil {
		return linuxBinaryAsset, applyReplace
	}
	if real, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = real
	}
	if exe == debInstallPath || !dirWritable(filepath.Dir(exe)) {
		return linuxDebAsset, applyBrowser
	}
	return linuxBinaryAsset, applyReplace
}

// dirWritable reports whether the running user can create files in dir (and
// therefore replace the binary there via write + rename).
func dirWritable(dir string) bool {
	f, err := os.CreateTemp(dir, ".syslogstudio-upd-*")
	if err != nil {
		return false
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return true
}
