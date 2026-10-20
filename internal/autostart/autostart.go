// Package autostart registers the desktop application to start when the user
// signs in — the user-session background mode.
//
// Each platform has one ordinary, per-user mechanism for this, and that is the
// one used: the Run key on Windows, a LaunchAgent on macOS, an XDG autostart
// entry on Linux. None needs an administrator, and each is what the user would
// find and remove by hand if they went looking — nothing is hidden.
//
// The registration launches the executable with BackgroundFlag, which starts
// it hidden in the tray rather than opening a window at every sign-in.
package autostart

import (
	"os"
	"path/filepath"
	"strings"
)

// BackgroundFlag is the argument the registered command carries.
const BackgroundFlag = "--background"

// Status is what is registered.
type Status struct {
	Supported bool
	// Enabled is whether anything is registered under our name.
	Enabled bool
	// Executable is the program the registration launches.
	Executable string
	// MatchesThis is whether that program is the one asking. A portable copy
	// that has moved leaves a registration pointing at where it used to be.
	MatchesThis bool
}

// Executable is the path of this program, symlinks resolved, as the
// registration should name it.
func Executable() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	return exe, nil
}

func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	a, b = filepath.Clean(a), filepath.Clean(b)
	if isCaseInsensitive {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// Get reports what is registered, compared with exe.
func Get(exe string) Status {
	registered, ok, supported := read()
	return Status{
		Supported:   supported,
		Enabled:     ok,
		Executable:  registered,
		MatchesThis: ok && samePath(registered, exe),
	}
}

// Enable registers exe to start at sign-in, replacing any registration of
// another copy.
func Enable(exe string) error {
	return write(exe)
}

// Disable removes the registration, whichever copy it named. Removing nothing
// is not an error.
func Disable() error {
	return remove()
}
