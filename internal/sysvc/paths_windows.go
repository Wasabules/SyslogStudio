//go:build windows

package sysvc

import (
	"errors"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Supported reports whether a system service can be installed here.
func Supported() bool { return true }

// DataDir is where the service keeps its configuration, database and keys:
// %ProgramData%\SyslogStudio, readable by administrators and the service only.
func DataDir() (string, error) {
	dir, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, Name), nil
}

// StatusDir is where the service publishes its status, the one part of its
// directory any local user may read: state, listeners, version and the last
// error — nothing received.
func StatusDir() (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "status"), nil
}

// LogPath is the service's own log file.
func LogPath() (string, error) {
	dir, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "logs", "service.log"), nil
}

// ErrLocation explains why a copy outside Program Files is refused.
var ErrLocation = errors.New("SyslogStudio must be installed for all users, in Program Files, to run as a service: " +
	"the service runs under a system account, and a copy that an ordinary user can replace " +
	"would hand that account to whoever replaces it")

// CheckLocation reports whether exe may be installed as a service: it must sit
// where only administrators can write. A portable copy, or one installed for
// the current user only, may not.
func CheckLocation(exe string) error {
	for _, id := range []*windows.KNOWNFOLDERID{windows.FOLDERID_ProgramFiles, windows.FOLDERID_ProgramFilesX86} {
		dir, err := windows.KnownFolderPath(id, 0)
		if err == nil && isUnder(exe, dir) {
			return nil
		}
	}
	return ErrLocation
}

func isUnder(path, dir string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
	if err != nil {
		return false
	}
	return rel != "." && !strings.HasPrefix(rel, "..") && !filepath.IsAbs(rel)
}

// ownLikeDir has nothing to do on Windows: a file written by an elevated
// administrator in someone's directory stays readable by them.
func ownLikeDir(string) {}
