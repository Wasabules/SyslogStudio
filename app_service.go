package main

import (
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"

	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/remote"
	"SyslogStudio/internal/updater"
	"SyslogStudio/internal/winsvc"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"
)

// --- Driving the system service ---------------------------------------------
//
// While the system service runs, it owns the receiver: the ports, the
// database, the rules. A window that kept driving an engine of its own would
// show a log nobody writes to and settings nobody uses — which is exactly
// what someone who installed the service found. So the window drives the
// service instead, over its pipe: the settings it changes are the service's,
// the messages it shows are the ones the service receives and stores.
//
// When the service stops, or was never installed, the window drives its own
// engine as before, and goes back to the service as soon as it runs again.
// Each switch reloads the interface, which then reads everything afresh from
// whichever engine it now drives.

const (
	linkLocal   = "local"
	linkService = "service"
)

const (
	// linkPoll is how often the window looks for the service.
	linkPoll = 3 * time.Second
	// dialTimeout bounds one attempt to connect to the service's pipe.
	dialTimeout = 2 * time.Second
	// reconnectFor is how long a lost connection is retried before the
	// window goes back to its own engine: long enough for the service to
	// restart, which is what an update or a newly allowed account does.
	reconnectFor = 15 * time.Second
)

// Why the window drives its own engine although the service is installed.
const (
	reasonStopped     = "stopped"
	reasonDenied      = "denied"
	reasonVersion     = "version"
	reasonNotService  = "notService"
	reasonUnreachable = "unreachable"
)

// serviceLink is which engine the window drives.
type serviceLink struct {
	mu sync.Mutex
	// client is set while the window drives the service.
	client *remote.Client
	// reason and detail say why it does not, when the service is installed.
	reason, detail string
	// started is set once startup has chosen, so the watcher has something
	// to watch.
	started bool
	// localOpened is whether the window's own engine was opened, and so
	// must be closed rather than dropped.
	localOpened bool
	// lettingGo is set while this window stops or removes the service
	// itself: the connection it loses is not coming back, and waiting for
	// it would only delay showing the window's own engine.
	lettingGo bool

	poke chan struct{}
	stop chan struct{}
	done chan struct{}
}

// local is the engine this window drives when it drives its own, nil while it
// drives the service.
func (a *App) local() *engine.Engine {
	a.link.mu.Lock()
	defer a.link.mu.Unlock()
	return a.engine
}

// keyMaterial is where certificate exports come from: the engine the window
// drives.
func (a *App) keyMaterial() keyMaterial {
	a.link.mu.Lock()
	defer a.link.mu.Unlock()
	if a.link.client != nil {
		return a.link.client
	}
	return a.engine
}

// drivingService reports whether the window drives the service.
func (a *App) drivingService() bool {
	a.link.mu.Lock()
	defer a.link.mu.Unlock()
	return a.link.client != nil
}

// GetServiceLink says which engine the window drives, and when it drives its
// own although the service is installed, why.
func (a *App) GetServiceLink() models.ServiceLink {
	a.link.mu.Lock()
	client, reason, detail := a.link.client, a.link.reason, a.link.detail
	a.link.mu.Unlock()

	link := models.ServiceLink{Mode: linkLocal}
	if client != nil {
		link.Mode = linkService
		link.ServiceVersion = client.Hello().Version
	} else {
		link.Reason = reason
		link.Detail = detail
	}
	if winsvc.Supported() {
		if info, err := winsvc.Query(); err == nil {
			link.Installed = info.Installed
			link.State = info.State
		}
	}
	if !link.Installed {
		link.Reason, link.Detail = "", ""
	}
	return link
}

// AllowServiceAccess lets this window's account drive the service. It takes
// an administrator; the service restarts so its pipe lets the account in, and
// the window connects as soon as it is back.
func (a *App) AllowServiceAccess() error {
	sid, err := winsvc.CurrentUserSID()
	if err != nil {
		return err
	}
	err = a.runServiceCommand("allow", "--operator", sid)
	a.pokeLink()
	return err
}

// lettingGoOfService runs fn — stopping or removing the service — telling the
// watcher that the connection it is about to lose is not coming back.
func (a *App) lettingGoOfService(fn func() error) error {
	a.link.mu.Lock()
	a.link.lettingGo = true
	a.link.mu.Unlock()
	err := fn()
	a.link.mu.Lock()
	a.link.lettingGo = false
	a.link.mu.Unlock()
	a.pokeLink()
	return err
}

// startLink chooses, at startup, which engine to drive: the service when it
// runs and lets this account in, the window's own otherwise.
func (a *App) startLink() {
	a.link.poke = make(chan struct{}, 1)
	a.link.stop = make(chan struct{})
	a.link.done = make(chan struct{})

	if c, reason, detail := a.dialService(); c != nil {
		a.useService(c, false)
	} else {
		a.setReason(reason, detail)
		a.openLocal()
	}
	a.link.mu.Lock()
	a.link.started = true
	a.link.mu.Unlock()
	go a.watchLink()
}

// stopLink stops watching and closes whatever the window drives.
func (a *App) stopLink() {
	a.link.mu.Lock()
	started := a.link.started
	a.link.mu.Unlock()
	if started {
		close(a.link.stop)
		<-a.link.done
	}
	a.link.mu.Lock()
	client, eng := a.link.client, a.engine
	a.link.mu.Unlock()
	if client != nil {
		client.Close()
	}
	if eng != nil {
		eng.Close()
	}
}

// pokeLink makes the watcher look now rather than at its next tick: after
// the service was started, stopped or allowed from here.
func (a *App) pokeLink() {
	if a.link.poke == nil {
		return
	}
	select {
	case a.link.poke <- struct{}{}:
	default:
	}
}

func (a *App) watchLink() {
	defer close(a.link.done)
	t := time.NewTicker(linkPoll)
	defer t.Stop()
	for {
		a.link.mu.Lock()
		client := a.link.client
		a.link.mu.Unlock()
		var lost <-chan struct{}
		if client != nil {
			lost = client.Done()
		}

		select {
		case <-a.link.stop:
			return
		case <-lost:
			a.reconnect(client)
		case <-t.C:
			if client == nil {
				a.tryService()
			}
		case <-a.link.poke:
			if client == nil {
				a.tryService()
			}
		}
	}
}

// tryService connects to the service if it now runs and lets this account in.
// Otherwise it records why not, for the banner.
func (a *App) tryService() {
	c, reason, detail := a.dialService()
	if c == nil {
		if a.setReason(reason, detail) {
			a.emit("service:link")
		}
		return
	}
	a.useService(c, true)
}

// reconnect follows a lost connection: the service restarting comes back
// within seconds, and the window carries on with it; a service that stays
// away leaves the window driving its own engine.
func (a *App) reconnect(lost *remote.Client) {
	a.link.mu.Lock()
	lettingGo := a.link.lettingGo
	a.link.mu.Unlock()
	if lettingGo {
		a.setReason(reasonStopped, "")
		a.useLocal()
		return
	}

	slog.Info("the connection to the service was lost; reconnecting", "error", lost.Err())
	deadline := time.Now().Add(reconnectFor)
	reason, detail := reasonUnreachable, ""
	for time.Now().Before(deadline) {
		select {
		case <-a.link.stop:
			return
		case <-time.After(500 * time.Millisecond):
		}
		var c *remote.Client
		c, reason, detail = a.dialService()
		if c != nil {
			a.useService(c, true)
			return
		}
		// A restart passes through stopped and unreachable; anything else —
		// removed, refused, replaced — is not going to change by waiting.
		if reason != reasonStopped && reason != reasonUnreachable {
			break
		}
	}
	a.setReason(reason, detail)
	a.useLocal()
}

// dialService connects to the service and introduces this window, or says
// why it cannot.
func (a *App) dialService() (c *remote.Client, reason, detail string) {
	if !winsvc.Supported() {
		return nil, "", ""
	}
	info, err := winsvc.Query()
	if err != nil || !info.Installed {
		return nil, "", ""
	}
	if info.State != "running" {
		return nil, reasonStopped, ""
	}
	conn, err := winsvc.DialControl(dialTimeout)
	switch {
	case errors.Is(err, winsvc.ErrAccessDenied):
		return nil, reasonDenied, ""
	case errors.Is(err, winsvc.ErrNotService):
		return nil, reasonNotService, err.Error()
	case err != nil:
		return nil, reasonUnreachable, err.Error()
	}
	client, err := remote.NewClient(conn, updater.GetAppVersion(), a.forwardEvent)
	var verr *remote.VersionError
	switch {
	case errors.As(err, &verr):
		return nil, reasonVersion, verr.Service
	case err != nil:
		return nil, reasonUnreachable, err.Error()
	}
	return client, "", ""
}

// setReason records why the window drives its own engine, and reports
// whether that changed.
func (a *App) setReason(reason, detail string) bool {
	a.link.mu.Lock()
	defer a.link.mu.Unlock()
	changed := a.link.reason != reason || a.link.detail != detail
	a.link.reason, a.link.detail = reason, detail
	return changed
}

// useService makes the window drive the service through c. Its own engine
// closes: the service has the ports, and the window's database is not the one
// being written.
func (a *App) useService(c *remote.Client, reload bool) {
	a.link.mu.Lock()
	old, oldClient := a.engine, a.link.client
	a.link.client = c
	a.link.reason, a.link.detail = "", ""
	a.engine = nil
	a.link.mu.Unlock()

	a.sw.Set(c)
	if oldClient != nil {
		oldClient.Close()
	}
	a.link.mu.Lock()
	opened := a.link.localOpened
	a.link.localOpened = false
	a.link.mu.Unlock()
	if old != nil && opened {
		old.Close()
	}
	slog.Info("this window now drives the service", "version", c.Hello().Version)
	if reload {
		a.emit("backend:changed")
	}
	a.refreshTrayStatus()
}

// useLocal makes the window drive its own engine again.
func (a *App) useLocal() {
	a.openLocal()
	slog.Info("this window now drives its own engine")
	a.emit("backend:changed")
	a.refreshTrayStatus()
}

// openLocal opens the window's own engine and makes it the one driven. It
// does not start receiving: the listeners start on launch only when the user
// asked for that, and a service going away is not a launch.
func (a *App) openLocal() {
	a.link.mu.Lock()
	eng := a.engine
	if eng == nil || a.link.localOpened {
		// A closed engine is not reopened: a fresh one, on the same store.
		eng = engine.New(a.prefs)
	}
	a.link.mu.Unlock()

	var emitter event.EventEmitter = silentEmitter{}
	if a.ctx != nil {
		emitter = event.NewWailsEventEmitter(a.ctx)
	}
	if err := eng.Open(emitter); err != nil {
		slog.Warn("the engine could not claim its data directory", "error", err)
	}

	a.link.mu.Lock()
	a.engine = eng
	a.link.client = nil
	a.link.localOpened = true
	a.link.mu.Unlock()
	a.sw.Set(eng)
}

// silentEmitter is the emitter of an engine opened with no window to show
// its events to: in tests.
type silentEmitter struct{}

func (silentEmitter) Emit(string, ...interface{}) {}

// forwardEvent passes what the service broadcasts to the frontend, as the
// in-process engine would have emitted it.
func (a *App) forwardEvent(name string, data []json.RawMessage) {
	if a.ctx == nil {
		return
	}
	args := make([]interface{}, len(data))
	for i, d := range data {
		args[i] = d
	}
	wailsRuntime.EventsEmit(a.ctx, name, args...)
	if name == "syslog:status" {
		a.refreshTrayStatus()
	}
}

func (a *App) emit(name string) {
	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, name)
	}
}
