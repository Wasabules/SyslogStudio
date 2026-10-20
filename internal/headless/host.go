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
	"os"
	"path/filepath"
	"sync"
	"time"

	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/models"
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
}

// Host is a running headless engine.
type Host struct {
	opts Options
	log  *slog.Logger
	eng  *engine.Engine

	stop chan struct{}
	done chan struct{}

	mu     sync.Mutex
	status models.HostStatus
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
	if err := h.eng.Open(newLogEmitter(h.log)); err != nil {
		h.eng.Close()
		return err
	}
	if err := h.eng.StartSaved(); err != nil {
		h.eng.Close()
		return fmt.Errorf("start the listeners: %w", err)
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
			h.refresh()
		case <-h.stop:
			return
		}
	}
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
	h.mu.Unlock()
	h.publish()
}

// Stop stops receiving, flushes the database and returns once it is closed.
func (h *Host) Stop() {
	close(h.stop)
	<-h.done
	h.refresh()
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
