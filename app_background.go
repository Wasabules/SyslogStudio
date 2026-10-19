package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"SyslogStudio/internal/autostart"
	"SyslogStudio/internal/headless"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/winsvc"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// --- Running in the background ---------------------------------------------
//
// Two modes, kept apart because they are for different people (#68).
//
// In the user's session: this application, started at sign-in, hidden in the
// tray, receiving with the user's own configuration until they sign out. It
// needs nobody's permission, and it is what most people mean by "in the
// background".
//
// As a system service: a separate headless copy that Windows starts at boot,
// before anyone signs in, under its own account and configuration. That is
// what an unattended machine needs, and installing it takes an administrator.

// elevatedTimeout bounds an elevated helper: the prompt is answered before the
// clock starts, so this is the work itself.
const elevatedTimeout = 2 * time.Minute

// backgroundState is what this run knows about how it started.
type backgroundState struct {
	mu sync.Mutex
	// launched is whether this run started hidden, from the sign-in
	// registration.
	launched bool
	// revealedForUnlock is set when a hidden start had to show the window
	// for the database password, so it can go back to the tray afterwards.
	revealedForUnlock bool
	autoStarted       bool
	autoStartErr      string
}

// GetBackgroundSettings reports the user-session mode.
func (a *App) GetBackgroundSettings() models.BackgroundSettings {
	exe, _ := autostart.Executable()
	reg := autostart.Get(exe)
	a.bg.mu.Lock()
	launched := a.bg.launched
	a.bg.mu.Unlock()

	s := models.BackgroundSettings{
		LaunchAtLogin:          reg.Enabled && reg.MatchesThis,
		LaunchAtLoginSupported: reg.Supported,
		AutoStartListeners:     a.prefs.LoadBackground().AutoStartListeners,
		LaunchedInBackground:   launched,
		TrayAvailable:          a.IsTrayAvailable(),
	}
	if reg.Enabled && !reg.MatchesThis {
		s.RegisteredElsewhere = reg.Executable
	}
	return s
}

// SetLaunchAtLogin registers this executable to start hidden when the user
// signs in, or removes the registration. Enabling replaces a registration of
// another copy.
func (a *App) SetLaunchAtLogin(enabled bool) error {
	if !enabled {
		return autostart.Disable()
	}
	exe, err := autostart.Executable()
	if err != nil {
		return err
	}
	return autostart.Enable(exe)
}

// SetAutoStartListeners records whether launching starts the listeners.
func (a *App) SetAutoStartListeners(enabled bool) {
	p := a.prefs.LoadBackground()
	p.AutoStartListeners = enabled
	a.prefs.SaveBackground(p)
}

// GetAutoStartError returns why starting the listeners on launch failed, once,
// so the window can say so; empty when it did not fail. Startup happens before
// the window has loaded, so an event sent then would reach nobody.
func (a *App) GetAutoStartError() string {
	a.bg.mu.Lock()
	defer a.bg.mu.Unlock()
	msg := a.bg.autoStartErr
	a.bg.autoStartErr = ""
	return msg
}

// GetDataDirConflict explains why this window cannot use its data directory —
// another SyslogStudio process has it — or returns empty.
func (a *App) GetDataDirConflict() string {
	if a.engine == nil || a.engine.OpenError() == nil {
		return ""
	}
	return a.engine.OpenError().Error()
}

// autoStart starts the listeners if the user asked for that on launch, as soon
// as the engine can: at startup, or right after the unlock when the database
// is encrypted. It runs once per launch.
func (a *App) autoStart() {
	if !a.prefs.LoadBackground().AutoStartListeners || a.engine.OpenError() != nil || a.IsEncryptionLocked() {
		return
	}
	a.bg.mu.Lock()
	if a.bg.autoStarted {
		a.bg.mu.Unlock()
		return
	}
	a.bg.autoStarted = true
	a.bg.mu.Unlock()

	if a.GetServerStatus().Running {
		return
	}
	if err := a.StartServer(a.GetDefaultConfig()); err != nil {
		slog.Warn("could not start the listeners on launch", "error", err)
		a.bg.mu.Lock()
		a.bg.autoStartErr = err.Error()
		a.bg.mu.Unlock()
	}
	a.refreshTrayStatus()
}

// afterStartup finishes a launch once the tray question is settled.
//
// A hidden start with no tray would be a process nobody can find, so it shows
// the window minimised instead. One with an encrypted database shows the
// window too: nothing can be stored until someone types the password, and a
// receiver silently not storing is the outcome this whole feature exists to
// avoid.
func (a *App) afterStartup(trayReady bool) {
	a.autoStart()

	a.bg.mu.Lock()
	launched := a.bg.launched
	a.bg.mu.Unlock()
	if !launched || a.ctx == nil {
		return
	}
	switch {
	case a.IsEncryptionLocked():
		a.bg.mu.Lock()
		a.bg.revealedForUnlock = true
		a.bg.mu.Unlock()
		a.RevealWindow()
	case !trayReady:
		wailsRuntime.WindowShow(a.ctx)
		wailsRuntime.WindowMinimise(a.ctx)
	}
}

// UnlockDatabase unlocks, then does what the lock was holding back: starting
// the listeners, and returning a hidden start to the tray.
func (a *App) UnlockDatabase(password string) error {
	if err := a.Backend.UnlockDatabase(password); err != nil {
		return err
	}
	a.autoStart()

	a.bg.mu.Lock()
	back := a.bg.revealedForUnlock
	a.bg.revealedForUnlock = false
	a.bg.mu.Unlock()
	if back && a.IsTrayAvailable() {
		a.HideToBackground()
	}
	return nil
}

// StartServer starts the listeners, and names the system service when it is
// the one holding a port: "address already in use" alone sends people looking
// for some other program.
func (a *App) StartServer(config models.ServerConfig) error {
	err := a.Backend.StartServer(config)
	if err == nil || !winsvc.Supported() {
		return err
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "only one usage") && !strings.Contains(msg, "address already in use") {
		return err
	}
	if info, qerr := winsvc.Query(); qerr == nil && info.Installed && info.State == "running" {
		return fmt.Errorf("%w — the SyslogStudio system service is running and listening; stop it, or use other ports here", err)
	}
	return err
}

// --- The system service ----------------------------------------------------

// GetSystemService reports the system service.
func (a *App) GetSystemService() models.SystemServiceInfo {
	info := models.SystemServiceInfo{Supported: winsvc.Supported()}
	if !info.Supported {
		return info
	}
	exe, _ := autostart.Executable()
	if err := winsvc.CheckLocation(exe); err != nil {
		info.CannotInstallReason = err.Error()
	} else {
		info.CanInstall = true
	}
	info.DataDir, _ = winsvc.DataDir()

	q, err := winsvc.Query()
	if err != nil {
		info.State = "unknown"
		return info
	}
	info.Installed = q.Installed
	info.State = q.State
	info.Executable = q.Executable
	info.Account = q.Account
	info.ExecutableMatches = q.Installed && strings.EqualFold(filepath.Clean(q.Executable), filepath.Clean(exe))
	if q.Installed {
		if dir, err := winsvc.StatusDir(); err == nil {
			if hs, ok := headless.ReadStatus(dir); ok {
				info.Host = &hs
			}
		}
	}
	return info
}

// InstallSystemService installs the system service with this window's
// configuration — or, when it is installed already, hands it the current
// configuration — and starts it.
//
// The work is split by privilege. This window, unprivileged, gathers the
// configuration — which needs the database unlocked when encryption is on —
// and writes it to a file only the user can read. An elevated copy of the
// executable, behind the administrator prompt, installs the service, writes
// the configuration into its directory and deletes the file.
//
// This window stops receiving first: the service takes the same ports, and
// starting it while they are held would fail. The listeners no longer start
// on launch either, since they would only collide with the service.
func (a *App) InstallSystemService() error {
	if !winsvc.Supported() {
		return winsvc.ErrUnsupported
	}
	exe, err := autostart.Executable()
	if err != nil {
		return err
	}
	if err := winsvc.CheckLocation(exe); err != nil {
		return err
	}
	bundle, err := a.keys.ExportBundle()
	if err != nil {
		return err
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		return err
	}

	dir, err := os.MkdirTemp("", "syslogstudio-install-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	bundlePath := filepath.Join(dir, "bundle.json")
	if err := os.WriteFile(bundlePath, data, 0600); err != nil {
		return err
	}

	wasRunning := a.GetServerStatus().Running
	hadAutoStart := a.prefs.LoadBackground().AutoStartListeners
	if wasRunning {
		if err := a.StopServer(); err != nil {
			return fmt.Errorf("stop receiving here first: %w", err)
		}
	}
	a.SetAutoStartListeners(false)
	a.refreshTrayStatus()

	err = a.runElevated(exe, dir, "install", "--bundle", bundlePath)
	if err != nil {
		// Declined or failed: nothing took the ports over, so this window goes
		// back to receiving the way it was rather than leaving the machine
		// with no receiver at all.
		a.SetAutoStartListeners(hadAutoStart)
		if wasRunning {
			if rerr := a.StartServer(a.GetDefaultConfig()); rerr != nil {
				slog.Warn("could not resume receiving after the service install failed", "error", rerr)
			}
		}
		a.refreshTrayStatus()
	}
	return err
}

// UninstallSystemService removes the service. purge also deletes its data —
// the messages it stored included.
func (a *App) UninstallSystemService(purge bool) error {
	args := []string{"uninstall"}
	if purge {
		args = append(args, "--purge")
	}
	return a.runServiceCommand(args...)
}

// StartSystemService starts the installed service.
func (a *App) StartSystemService() error { return a.runServiceCommand("start") }

// StopSystemService stops it.
func (a *App) StopSystemService() error { return a.runServiceCommand("stop") }

func (a *App) runServiceCommand(args ...string) error {
	if !winsvc.Supported() {
		return winsvc.ErrUnsupported
	}
	exe, err := autostart.Executable()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "syslogstudio-service-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	return a.runElevated(exe, dir, args...)
}

// runElevated runs `exe service <args>` as an administrator and returns what
// it reported.
func (a *App) runElevated(exe, dir string, args ...string) error {
	resultPath := filepath.Join(dir, "result.json")
	full := append([]string{"service"}, args...)
	full = append(full, "--result", resultPath)

	code, err := winsvc.RunElevated(exe, full, elevatedTimeout)
	if err != nil {
		if errors.Is(err, winsvc.ErrCancelled) {
			return fmt.Errorf("cancelled: administrator rights are needed for this")
		}
		return err
	}
	if r, rerr := winsvc.ReadResult(resultPath); rerr == nil {
		if !r.OK {
			return errors.New(r.Error)
		}
		return nil
	}
	if code != 0 {
		return fmt.Errorf("the administrator step failed (exit code %d)", code)
	}
	return nil
}
