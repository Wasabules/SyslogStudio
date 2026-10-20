// Package headless runs the engine with no window: the listeners, the
// database, the alert rules and the routing, started from a saved
// configuration and kept running until told to stop.
//
// It is what the Windows service runs, and what `SyslogStudio --headless`
// runs in a terminal or under systemd or launchd. Both are the same thing with
// a different supervisor, so they share this one implementation.
package headless

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/remote"
	"SyslogStudio/internal/storage"
)

// StatusFileName is what a host writes into its status directory.
const StatusFileName = "status.json"

// statusInterval is how often the published status is refreshed while
// running, so a reader can tell a live host from one that died without
// rewriting it.
const statusInterval = 30 * time.Second

// Options configure a host.
type Options struct {
	// DataDir holds the configuration, the database and the keys.
	DataDir string
	// StatusDir is where status.json is published, readable by people who
	// may not read DataDir. Empty means DataDir.
	StatusDir string
	// Sealer protects credentials and keys at rest when there is no
	// password, which for a headless host is always.
	Sealer storage.Sealer
	// Version is reported in the status.
	Version string
	// Logger receives what the host has to say. Nil means slog.Default().
	Logger *slog.Logger
	// Control, when set, is where windows connect to drive this host's
	// engine: its settings, its messages, its rules (see package remote).
	// Who may connect is the listener's business. The host serves it until
	// it stops, and closes it.
	Control net.Listener
}

// Host is a running headless engine.
type Host struct {
	opts   Options
	log    *slog.Logger
	eng    *engine.Engine
	server *remote.Server

	stop     chan struct{}
	done     chan struct{}
	stopOnce sync.Once

	mu     sync.Mutex
	status models.HostStatus
	// retry is set while the saved listeners have not started: a host that
	// windows can reach keeps running so they can fix the settings, and
	// tries again meanwhile in case what held a port lets go of it.
	retry bool
}

// ErrEncrypted means the configuration has at-rest encryption on. A headless
// host has nobody to type the password, and without it every message would
// be received and none stored — so it refuses rather than run like that.
var ErrEncrypted = errors.New("the database is encrypted, and a headless host has no one to unlock it; use a data directory without at-rest encryption")

// Start opens the engine on the data directory and starts receiving with the
// saved configuration. It returns once the listeners are up, or with the
// reason they are not.
func Start(opts Options) (*Host, error) {
	if opts.StatusDir == "" {
		opts.StatusDir = opts.DataDir
	}
	log := opts.Logger
	if log == nil {
		log = slog.Default()
	}
	h := &Host{
		opts: opts,
		log:  log,
		stop: make(chan struct{}),
		done: make(chan struct{}),
		status: models.HostStatus{
			State:     "starting",
			Version:   opts.Version,
			PID:       os.Getpid(),
			DataDir:   opts.DataDir,
			StartedAt: time.Now(),
		},
	}

	if err := h.start(); err != nil {
		if opts.Control != nil {
			opts.Control.Close()
		}
		h.fail(err)
		return nil, err
	}

	h.mu.Lock()
	h.status.State = "running"
	h.mu.Unlock()
	h.refresh()
	go h.loop()
	return h, nil
}

func (h *Host) start() error {
	if h.opts.DataDir == "" {
		return fmt.Errorf("no data directory")
	}
	if err := os.MkdirAll(h.opts.DataDir, 0700); err != nil {
		return fmt.Errorf("create the data directory: %w", err)
	}
	cs := storage.NewConfigStoreAt(h.opts.DataDir)
	if cs.LoadStorage().EncryptionEnabled {
		return ErrEncrypted
	}

	h.eng = engine.New(cs)
	if h.opts.Sealer != nil {
		h.eng.SetSealer(h.opts.Sealer)
	}
	var emitter event.EventEmitter = newLogEmitter(h.log)
	if h.opts.Control != nil {
		h.server = remote.NewServer(controlled{Engine: h.eng, host: h}, h.opts.Version, h.log)
		emitter = fanout{emitter, h.server}
	}
	if err := h.eng.Open(emitter); err != nil {
		h.eng.Close()
		return err
	}
	// Listening waits for a window only on a host windows can reach: one
	// nobody can drive would wait for ever.
	if h.server != nil && !h.eng.GetListenOnStart() {
		h.log.Info("listening on start is off; the listeners wait for a window to start them")
	} else if err := h.eng.StartSaved(); err != nil {
		if h.server == nil {
			h.eng.Close()
			return fmt.Errorf("start the listeners: %w", err)
		}
		// Nobody can fix the settings of a host that exits; a window can
		// fix those of one that runs.
		h.log.Error("the listeners did not start; waiting for a window to fix the settings", "error", err)
		h.status.Error = "start the listeners: " + err.Error()
		h.retry = true
	}
	if h.server != nil {
		go func() {
			if err := h.server.Serve(h.opts.Control); err != nil {
				h.log.Error("windows can no longer connect", "error", err)
			}
		}()
	}

	st := h.eng.GetServerStatus()
	h.log.Info("receiving", "listeners", describeListeners(st), "dataDir", h.opts.DataDir)
	return nil
}

// fail records why the host could not start. When the reason is that another
// host owns the directory, nothing is published: the status file is that
// host's, and overwriting it would report a running receiver as failed.
func (h *Host) fail(err error) {
	h.mu.Lock()
	h.status.State = "failed"
	h.status.Error = err.Error()
	h.mu.Unlock()
	h.log.Error("could not start", "error", err)
	if !errors.Is(err, storage.ErrDirInUse) {
		h.publish()
	}
}

func (h *Host) loop() {
	defer close(h.done)
	t := time.NewTicker(statusInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			h.retryListeners()
			h.refresh()
		case <-h.stop:
			return
		}
	}
}

// retryListeners starts the saved listeners again while they have not all
// started. It stops trying once they all run, or once a window starts or
// stops them: from then on the window is in charge.
func (h *Host) retryListeners() {
	h.mu.Lock()
	retry := h.retry
	h.mu.Unlock()
	if !retry || h.eng == nil {
		return
	}
	// A partial start leaves the receiver running with a listener missing;
	// it has to stop before it can start again.
	if st := h.eng.GetServerStatus(); !allListening(st) {
		if st.Running {
			_ = h.eng.StopServer()
		}
		if err := h.eng.StartSaved(); err != nil {
			h.mu.Lock()
			h.status.Error = "start the listeners: " + err.Error()
			h.mu.Unlock()
			return
		}
		h.log.Info("receiving", "listeners", describeListeners(h.eng.GetServerStatus()))
	}
	h.windowTookOver()
}

// windowTookOver stops the retries, and clears the error they report.
func (h *Host) windowTookOver() {
	h.mu.Lock()
	h.retry = false
	h.status.Error = ""
	h.mu.Unlock()
}

// allListening reports whether every enabled listener runs.
func allListening(st models.ServerStatus) bool {
	if !st.Running {
		return false
	}
	for _, l := range listeners(st) {
		if !l.Running {
			return false
		}
	}
	return true
}

// refresh reads the engine's state into the published status.
func (h *Host) refresh() {
	if h.eng == nil {
		return
	}
	st := h.eng.GetServerStatus()
	stats := h.eng.GetStats()
	h.mu.Lock()
	h.status.Listeners = listeners(st)
	h.status.Messages = stats.TotalMessages
	h.status.ListenOnStart = true
	if h.server != nil {
		h.status.Windows = h.server.Windows()
		h.status.ListenOnStart = h.eng.GetListenOnStart()
	}
	h.mu.Unlock()
	h.publish()
}

// Stop stops receiving, flushes the database and returns once it is closed.
// Stopping again does nothing.
func (h *Host) Stop() {
	h.stopOnce.Do(h.shutdown)
}

func (h *Host) shutdown() {
	close(h.stop)
	<-h.done
	h.refresh()
	// Windows first, so none is in the middle of a call while the engine
	// closes under it.
	if h.server != nil {
		h.server.Close()
	}
	h.eng.Close()
	h.mu.Lock()
	h.status.State = "stopped"
	h.status.Listeners = nil
	h.mu.Unlock()
	h.publish()
	h.log.Info("stopped")
}

// Status is the host's current published status.
func (h *Host) Status() models.HostStatus {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.status
}

// publish writes status.json, through a temporary file so a reader never sees
// half of it.
func (h *Host) publish() {
	h.mu.Lock()
	h.status.UpdatedAt = time.Now()
	data, err := json.MarshalIndent(h.status, "", "  ")
	h.mu.Unlock()
	if err != nil || h.opts.StatusDir == "" {
		return
	}
	if err := os.MkdirAll(h.opts.StatusDir, 0755); err != nil {
		h.log.Warn("cannot publish status", "error", err)
		return
	}
	path := filepath.Join(h.opts.StatusDir, StatusFileName)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		h.log.Warn("cannot publish status", "error", err)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		h.log.Warn("cannot publish status", "error", err)
	}
}

// ReadStatus reads what a host last published in dir. ok is false when there
// is nothing to read.
func ReadStatus(dir string) (models.HostStatus, bool) {
	data, err := os.ReadFile(filepath.Join(dir, StatusFileName))
	if err != nil {
		return models.HostStatus{}, false
	}
	var st models.HostStatus
	if json.Unmarshal(data, &st) != nil {
		return models.HostStatus{}, false
	}
	return st, true
}

func listeners(st models.ServerStatus) []models.HostListener {
	var out []models.HostListener
	if st.Config.UDPEnabled {
		out = append(out, models.HostListener{Protocol: "udp", Port: st.Config.UDPPort, Running: st.UDPRunning})
	}
	if st.Config.TCPEnabled {
		out = append(out, models.HostListener{Protocol: "tcp", Port: st.Config.TCPPort, Running: st.TCPRunning})
	}
	if st.Config.TLSEnabled {
		out = append(out, models.HostListener{Protocol: "tls", Port: st.Config.TLSPort, Running: st.TLSRunning})
	}
	return out
}

func describeListeners(st models.ServerStatus) string {
	s := ""
	for _, l := range listeners(st) {
		if !l.Running {
			continue
		}
		if s != "" {
			s += ", "
		}
		s += fmt.Sprintf("%s/%d", l.Protocol, l.Port)
	}
	if s == "" {
		return "none"
	}
	return s
}

// fanout sends each event to several emitters: the log, and the windows.
type fanout []event.EventEmitter

func (f fanout) Emit(name string, data ...interface{}) {
	for _, e := range f {
		e.Emit(name, data...)
	}
}
