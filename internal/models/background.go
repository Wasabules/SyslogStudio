package models

import "time"

// Running without a window comes in two forms, and they are different things
// for different people, so the types keep them apart.
//
// In the user's session: the desktop application, started when the user signs
// in, hidden in the tray, under their account and with their configuration. It
// stops when they sign out. Nothing needs an administrator.
//
// As a system service: a separate, headless process that Windows starts at
// boot, before anyone signs in, under its own account and with its own
// configuration in a machine-wide directory. Installing it needs an
// administrator, once.

// BackgroundPrefs are the desktop application's own start-up choices.
type BackgroundPrefs struct {
	// AutoStartListeners starts receiving on launch with the saved
	// configuration, without anyone pressing Start.
	AutoStartListeners bool `json:"autoStartListeners"`
}

// BackgroundSettings is what the settings page shows about the user-session
// mode.
type BackgroundSettings struct {
	// LaunchAtLogin is whether this executable is registered to start when the
	// user signs in. It is read from the operating system, not from a saved
	// preference, so it cannot claim a registration that is not there.
	LaunchAtLogin bool `json:"launchAtLogin"`
	// LaunchAtLoginSupported is false where there is no mechanism to use.
	LaunchAtLoginSupported bool `json:"launchAtLoginSupported"`
	// RegisteredElsewhere is the path of another executable registered under
	// our name — a portable copy that has since moved — or empty.
	RegisteredElsewhere string `json:"registeredElsewhere"`
	AutoStartListeners  bool   `json:"autoStartListeners"`
	// LaunchedInBackground is whether this run started hidden.
	LaunchedInBackground bool `json:"launchedInBackground"`
	TrayAvailable        bool `json:"trayAvailable"`
}

// SystemServiceInfo is what the settings page shows about the system service.
type SystemServiceInfo struct {
	// Supported is false outside Windows, where the headless mode is run by
	// the platform's own service manager instead.
	Supported bool `json:"supported"`
	Installed bool `json:"installed"`
	// State is the service manager's view: stopped, starting, running,
	// stopping, or unknown.
	State string `json:"state"`
	// CanInstall says whether this executable may be installed as a service,
	// and CannotInstallReason why not when it may not.
	CanInstall          bool   `json:"canInstall"`
	CannotInstallReason string `json:"cannotInstallReason"`
	// ExecutableMatches is false when the installed service runs another copy
	// of SyslogStudio than this one.
	ExecutableMatches bool   `json:"executableMatches"`
	Executable        string `json:"executable"`
	Account           string `json:"account"`
	DataDir           string `json:"dataDir"`
	// Host is what the service itself last reported, when it has.
	Host *HostStatus `json:"host,omitempty"`
}

// HostStatus is what a headless host publishes about itself, for anyone
// allowed to look — the desktop application, a support script — without
// reading its data directory.
type HostStatus struct {
	// State is starting, running, stopped or failed.
	State     string         `json:"state"`
	Version   string         `json:"version"`
	PID       int            `json:"pid"`
	DataDir   string         `json:"dataDir"`
	StartedAt time.Time      `json:"startedAt"`
	UpdatedAt time.Time      `json:"updatedAt"`
	Listeners []HostListener `json:"listeners"`
	Messages  int64          `json:"messages"`
	// Error is why the host failed or stopped, in words an operator can act on.
	Error string `json:"error,omitempty"`
}

// HostListener is one listener of a headless host.
type HostListener struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Running  bool   `json:"running"`
}
