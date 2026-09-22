// Package tray puts SyslogStudio in the system notification area so it can go
// on receiving, storing and routing messages with no window open.
//
// Everything here is deliberately fail-soft. A tray is not guaranteed to
// exist: a bare Linux session may run no StatusNotifierItem host at all, and a
// locked-down desktop can refuse the registration. So Start reports whether an
// icon actually appeared, and the caller uses that answer to decide what
// closing the window is allowed to do. Getting this wrong produces the worst
// possible outcome — a process the user can neither see nor quit — so the
// failure path is the one designed first.
//
// The approach follows the one proven in SnmpLens: systray's external loop, so
// the toolkit does not fight Wails for the main thread.
package tray

import (
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"fyne.io/systray"
)

// Options describes the menu to build. Every callback is optional.
type Options struct {
	// Icon is the image bytes: an .ico on Windows, a .png elsewhere.
	Icon []byte
	// Tooltip is the hover text on the icon itself.
	Tooltip string
	// Labels are the menu entries, in English. The renderer replaces them once
	// svelte-i18n knows the user's locale — Go has no translations of its own,
	// and inventing a second catalogue would guarantee drift.
	Labels Labels
	// OnShow restores the main window.
	OnShow func()
	// OnQuit really exits, as opposed to hiding.
	OnQuit func()
}

// Labels are the tray menu strings.
type Labels struct {
	Show   string
	Quit   string
	Status string
}

// DefaultLabels are the English fallbacks used until the renderer reports a
// locale.
func DefaultLabels() Labels {
	return Labels{Show: "Open SyslogStudio", Quit: "Quit", Status: "Receiver stopped"}
}

// Controller manipulates a running tray icon.
type Controller struct {
	mu     sync.Mutex
	items  menuItems
	stop   func()
	live   bool
	closed bool
}

type menuItems struct {
	show   *systray.MenuItem
	status *systray.MenuItem
	quit   *systray.MenuItem
}

// readyTimeout bounds how long we wait for the desktop to accept the icon.
// Without it, a session with no tray host would hang startup: systray's
// registration simply never calls back rather than returning an error.
const readyTimeout = 5 * time.Second

// Start installs the tray icon.
//
// It reports ok=false when no icon could be shown, which is a normal outcome on
// some desktops and never an error worth interrupting startup for.
func Start(opts Options) (c *Controller, ok bool) {
	if opts.Labels.Show == "" {
		opts.Labels = DefaultLabels()
	}

	ctrl := &Controller{}
	ready := make(chan struct{})

	onReady := func() {
		// A panic in the toolkit callback would otherwise take the whole
		// process down for what is a convenience feature.
		defer func() {
			if r := recover(); r != nil {
				slog.Warn("tray registration panicked; continuing without an icon", "error", r)
			}
		}()

		if len(opts.Icon) > 0 {
			systray.SetIcon(opts.Icon)
		}
		if opts.Tooltip != "" {
			systray.SetTooltip(opts.Tooltip)
		}

		show := systray.AddMenuItem(opts.Labels.Show, "")
		systray.AddSeparator()
		status := systray.AddMenuItem(opts.Labels.Status, "")
		status.Disable() // a read-out, not a command
		systray.AddSeparator()
		quit := systray.AddMenuItem(opts.Labels.Quit, "")

		ctrl.mu.Lock()
		ctrl.items = menuItems{show: show, status: status, quit: quit}
		ctrl.live = true
		ctrl.mu.Unlock()

		go func() {
			for {
				select {
				case <-show.ClickedCh:
					if opts.OnShow != nil {
						opts.OnShow()
					}
				case <-quit.ClickedCh:
					if opts.OnQuit != nil {
						opts.OnQuit()
					}
					return
				}
			}
		}()

		close(ready)
	}

	start, end := systray.RunWithExternalLoop(onReady, func() {})
	ctrl.stop = end

	// start() blocks on some platforms and not others; a goroutine makes that
	// difference stop mattering.
	go func() {
		defer func() {
			if r := recover(); r != nil {
				slog.Warn("tray event loop panicked", "error", r)
			}
		}()
		start()
	}()

	select {
	case <-ready:
		return ctrl, true
	case <-time.After(readyTimeout):
		slog.Info("no system tray answered; running without one",
			"waited", readyTimeout, "os", runtime.GOOS)
		ctrl.Stop()
		return nil, false
	}
}

// SetStatus rewrites the disabled read-out line.
func (c *Controller) SetStatus(text string) {
	if c == nil || text == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.live && c.items.status != nil {
		c.items.status.SetTitle(text)
	}
}

// SetLabels replaces the menu wording, so the tray follows the language chosen
// in the application rather than being permanently English.
func (c *Controller) SetLabels(l Labels) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.live {
		return
	}
	if l.Show != "" && c.items.show != nil {
		c.items.show.SetTitle(l.Show)
	}
	if l.Quit != "" && c.items.quit != nil {
		c.items.quit.SetTitle(l.Quit)
	}
	if l.Status != "" && c.items.status != nil {
		c.items.status.SetTitle(l.Status)
	}
}

// Stop removes the icon. Safe to call twice, and safe on a nil receiver so
// callers do not have to branch on whether the tray ever started.
func (c *Controller) Stop() {
	if c == nil {
		return
	}
	c.mu.Lock()
	already := c.closed
	c.closed = true
	stop := c.stop
	c.mu.Unlock()

	if already || stop == nil {
		return
	}
	defer func() {
		if r := recover(); r != nil {
			slog.Warn("tray shutdown panicked", "error", r)
		}
	}()
	stop()
}

// StatusLine renders the read-out shown in the menu: what someone who cannot
// see the window wants to know about a syslog receiver.
func StatusLine(running bool, listeners []string, messages int64) string {
	if !running {
		return "Receiver stopped"
	}
	where := "no listener"
	if len(listeners) > 0 {
		where = joinShort(listeners)
	}
	return fmt.Sprintf("Receiving on %s · %d messages", where, messages)
}

func joinShort(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}
