//go:build windows

package updater

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const (
	windowsSetupAsset  = "SyslogStudio-windows-amd64-setup.exe"
	windowsBinaryAsset = "SyslogStudio-windows-amd64.exe"
)

// target selects the Windows asset and apply mode. An installed copy (via the
// NSIS installer) updates by running the new setup; a portable copy
// self-replaces the exe.
func target() (string, applyMode) {
	if isInstalled() {
		return windowsSetupAsset, applyInstaller
	}
	return windowsBinaryAsset, applyReplace
}

// isInstalled reports whether SyslogStudio was installed by the NSIS installer.
// The installer's uninstall key name is "<CompanyName>SyslogStudio", which is
// awkward to reconstruct, so we enumerate the Uninstall keys and match on
// DisplayName instead. Falls back to a path heuristic.
func isInstalled() bool {
	const uninstall = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	for _, root := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		if hasUninstallEntry(root, uninstall) {
			return true
		}
	}
	// Fallback: the exe lives under a typical install location.
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	dir := strings.ToLower(filepath.Dir(exe))
	if pf := os.Getenv("ProgramFiles"); pf != "" && strings.HasPrefix(dir, strings.ToLower(pf)) {
		return true
	}
	if la := os.Getenv("LOCALAPPDATA"); la != "" &&
		strings.HasPrefix(dir, strings.ToLower(filepath.Join(la, "SyslogStudio"))) {
		return true
	}
	return false
}

func hasUninstallEntry(root registry.Key, path string) bool {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return false
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return false
	}
	for _, name := range names {
		sub, err := registry.OpenKey(root, path+`\`+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		dn, _, err := sub.GetStringValue("DisplayName")
		sub.Close()
		if err == nil && dn == "SyslogStudio" {
			return true
		}
	}
	return false
}
