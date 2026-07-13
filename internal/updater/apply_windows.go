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

// target selects the Windows asset and apply mode. The NSIS-installed copy
// updates by running the new setup; a portable copy self-replaces the exe.
func target() (string, applyMode) {
	if isInstalled() {
		return windowsSetupAsset, applyInstaller
	}
	return windowsBinaryAsset, applyReplace
}

// isInstalled reports whether the RUNNING executable is the NSIS-installed copy,
// not merely that an install exists somewhere. A portable exe on a machine that
// also has an install must self-replace itself, not launch the installer
// against the other copy.
func isInstalled() bool {
	exe, err := os.Executable()
	if err != nil {
		return false
	}
	if real, rerr := filepath.EvalSymlinks(exe); rerr == nil {
		exe = real
	}
	dir := strings.ToLower(filepath.Dir(exe))

	if loc, ok := installLocation(); ok && loc != "" {
		// An install is registered: this exe is "installed" only if it lives
		// under that location.
		return pathUnder(dir, loc)
	}

	// No registry entry: fall back to a path heuristic.
	if pf := os.Getenv("ProgramFiles"); pf != "" && pathUnder(dir, pf) {
		return true
	}
	if la := os.Getenv("LOCALAPPDATA"); la != "" &&
		pathUnder(dir, filepath.Join(la, "SyslogStudio")) {
		return true
	}
	return false
}

// pathUnder reports whether dir is base or a subdirectory of it, comparing on
// cleaned, lowercased paths with a separator boundary. A raw prefix match would
// misclassify siblings — e.g. treat "...\SyslogStudio Portable" as under
// "...\SyslogStudio", or fail to match when InstallLocation carries a trailing
// separator that filepath.Dir(exe) does not.
func pathUnder(dir, base string) bool {
	if base == "" {
		return false
	}
	dir = strings.ToLower(filepath.Clean(dir))
	base = strings.ToLower(filepath.Clean(base))
	return dir == base || strings.HasPrefix(dir, base+string(os.PathSeparator))
}

// installLocation returns the install directory recorded by the NSIS installer,
// matched by DisplayName across HKCU (per-user) then HKLM (all-users).
func installLocation() (string, bool) {
	const uninstall = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	for _, root := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		if loc, ok := findInstallLocation(root, uninstall); ok {
			return loc, true
		}
	}
	return "", false
}

func findInstallLocation(root registry.Key, path string) (string, bool) {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return "", false
	}
	defer k.Close()
	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return "", false
	}
	for _, name := range names {
		sub, err := registry.OpenKey(root, path+`\`+name, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		dn, _, dnErr := sub.GetStringValue("DisplayName")
		if dnErr == nil && dn == "SyslogStudio" {
			loc, _, _ := sub.GetStringValue("InstallLocation")
			sub.Close()
			return loc, true
		}
		sub.Close()
	}
	return "", false
}
