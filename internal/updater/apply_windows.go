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
	return installedAt(filepath.Dir(exe), installLocations(), os.Getenv("ProgramFiles"), os.Getenv("LOCALAPPDATA"))
}

// installedAt is isInstalled's decision for the directory of the running
// executable. A per-user and an all-users copy can both be registered, so the
// executable is installed when it lives under any registered location.
func installedAt(dir string, registered []string, programFiles, localAppData string) bool {
	if len(registered) > 0 {
		for _, loc := range registered {
			if pathUnder(dir, loc) {
				return true
			}
		}
		return false
	}

	// No registry entry: fall back to a path heuristic.
	if programFiles != "" && pathUnder(dir, programFiles) {
		return true
	}
	if localAppData != "" && pathUnder(dir, filepath.Join(localAppData, "SyslogStudio")) {
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

// installLocations returns the install directories recorded by the NSIS
// installer, matched by DisplayName: the per-user one (HKCU) and the
// all-users one (HKLM), whichever exist. Both can.
func installLocations() []string {
	const uninstall = `Software\Microsoft\Windows\CurrentVersion\Uninstall`
	var locs []string
	for _, root := range []registry.Key{registry.CURRENT_USER, registry.LOCAL_MACHINE} {
		if loc, ok := findInstallLocation(root, uninstall); ok && loc != "" {
			locs = append(locs, loc)
		}
	}
	return locs
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
