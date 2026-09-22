package main

import (
	"strconv"
	"sync"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/tray"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// --- Closing the window -----------------------------------------------------
//
// A syslog receiver is a thing you want left running, so pressing the close
// button is genuinely ambiguous: it can mean "stop listening" or "get out of my
// way". So the application asks — quit, keep running in the background, or
// cancel — and remembers the answer if told to.
//
// The interception lives in OnBeforeClose, not in Wails's HideWindowOnClose.
// That option is fixed at startup, before we know whether a tray icon actually
// appeared, and an application that refuses to close with no tray to quit from
// is one you have to reach for the task manager to escape.
//
// Two ways back to a hidden window, and the second exists because the first is
// not guaranteed: the tray icon, and relaunching the executable, which the
// single-instance lock turns into "reveal the one already running".

// windowState holds what the close dialog needs. Separate from App's own
// fields because main.go touches it before App has a context.
type windowState struct {
	mu sync.Mutex
	// trayReady is whether an icon actually appeared. It decides whether
	// hiding is offered as a normal option or as the fallback it becomes
	// without one.
	trayReady bool
	ctrl      *tray.Controller
	// quitting is set once a real exit is under way, so the second close
	// event Wails delivers is not answered with a second dialog.
	quitting bool
}

var window windowState

// setTray records the outcome of the tray registration.
func setTray(ctrl *tray.Controller, ok bool) {
	window.mu.Lock()
	window.ctrl = ctrl
	window.trayReady = ok
	window.mu.Unlock()
}

// trayController returns the live controller, or nil.
func trayController() *tray.Controller {
	window.mu.Lock()
	defer window.mu.Unlock()
	return window.ctrl
}

// IsTrayAvailable tells the dialog whether a tray icon is there to come back
// from. Without one the background option still works — relaunching reveals the
// window — but the dialog says so rather than leaving the reader to find out.
func (a *App) IsTrayAvailable() bool {
	window.mu.Lock()
	defer window.mu.Unlock()
	return window.trayReady
}

// GetCloseAction reports what the close button currently does.
func (a *App) GetCloseAction() string {
	return string(a.configStore.LoadCloseAction())
}

// SetCloseAction records the choice, so the dialog can stop appearing. An
// unknown value is ignored by the store rather than written, which keeps
// "ask" as the state that cannot be corrupted into a silent decision.
func (a *App) SetCloseAction(action string) {
	a.configStore.SaveCloseAction(models.CloseAction(action))
}

// beforeClose runs when the window is about to close. Returning true swallows
// the close.
//
// It never decides anything itself beyond the remembered preference: when the
// answer is "ask", it hands the question to the renderer and swallows the
// close, and the renderer calls back into one of the three methods below.
func (a *App) beforeClose() bool {
	window.mu.Lock()
	if window.quitting {
		window.mu.Unlock()
		return false // a real quit is already under way; let it through
	}
	window.mu.Unlock()

	switch a.configStore.LoadCloseAction() {
	case models.CloseQuit:
		a.markQuitting()
		return false

	case models.CloseBackground:
		a.HideToBackground()
		return true

	default:
		// Ask. The renderer owns the dialog so it is the application's own
		// styling and the user's own language, rather than a native box that
		// looks like it came from somewhere else.
		if a.ctx != nil {
			wailsRuntime.EventsEmit(a.ctx, "app:closeRequested")
		}
		return true
	}
}

// markQuitting records that an exit is under way, so the close that follows is
// not intercepted a second time.
func (a *App) markQuitting() {
	window.mu.Lock()
	window.quitting = true
	window.mu.Unlock()
}

// QuitApplication exits for real. Called by the dialog and by the tray menu.
func (a *App) QuitApplication() {
	a.markQuitting()
	if a.ctx != nil {
		wailsRuntime.Quit(a.ctx)
	}
}

// HideToBackground hides the window and leaves everything running: the
// listeners keep receiving, the database keeps being written, and routing keeps
// delivering. That is the whole point of the feature.
func (a *App) HideToBackground() {
	if a.ctx == nil {
		return
	}
	wailsRuntime.WindowHide(a.ctx)
	a.refreshTrayStatus()
}

// RevealWindow brings a hidden window back. Called by the tray's Open entry and
// by the single-instance lock when the executable is launched again.
func (a *App) RevealWindow() {
	if a.ctx == nil {
		return
	}
	wailsRuntime.WindowShow(a.ctx)
	wailsRuntime.WindowUnminimise(a.ctx)
}

// CancelClose is what the dialog's third button calls. It exists as a binding
// rather than being handled entirely in the renderer so that closing is one
// conversation with one place that ends it.
func (a *App) CancelClose() {}

// SetTrayLabels lets the renderer translate the tray menu. Go carries no
// translations of its own, and a second catalogue would drift from the one the
// interface actually uses.
func (a *App) SetTrayLabels(show, quit string) {
	trayController().SetLabels(tray.Labels{Show: show, Quit: quit})
}

// refreshTrayStatus rewrites the read-out line with what someone who cannot see
// the window would want to know.
func (a *App) refreshTrayStatus() {
	ctrl := trayController()
	if ctrl == nil || a.server == nil {
		return
	}
	status := a.server.GetStatus()
	stats := a.server.GetStats()

	var listeners []string
	if status.UDPRunning {
		listeners = append(listeners, "UDP:"+strconv.Itoa(status.Config.UDPPort))
	}
	if status.TCPRunning {
		listeners = append(listeners, "TCP:"+strconv.Itoa(status.Config.TCPPort))
	}
	if status.TLSRunning {
		listeners = append(listeners, "TLS:"+strconv.Itoa(status.Config.TLSPort))
	}
	ctrl.SetStatus(tray.StatusLine(status.Running, listeners, stats.TotalMessages))
}
