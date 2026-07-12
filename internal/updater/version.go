package updater

// AppVersion is the running application version. It is injected at build time
// via ldflags:
//
//	-X SyslogStudio/internal/updater.AppVersion=<tag>
//
// It stays "dev" for local/unversioned builds, for which update checks are
// skipped.
var AppVersion = "dev"

// GetAppVersion returns the current version string (unmodified).
func GetAppVersion() string { return AppVersion }

// isDevVersion reports whether this is an unversioned dev build.
func isDevVersion() bool { return AppVersion == "" || AppVersion == "dev" }
