// Package engine is the receiver itself: the listeners, the database, the
// alert rules, the routing, the certificates — everything SyslogStudio does
// that does not need a window.
//
// It used to live inside the Wails facade, which made the window the only
// thing that could run it. Pulled out here, the same engine is hosted either
// in-process by the desktop application or by a headless process with no
// window at all — a background service that starts before anyone logs in.
// Nothing in this package may import Wails: the one link to the interface is
// the event.EventEmitter it is opened with.
package engine

import (
	"fmt"
	"log/slog"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/notify"
	"SyslogStudio/internal/pki"
	"SyslogStudio/internal/simulator"
	"SyslogStudio/internal/storage"
	"SyslogStudio/internal/syslog"
)

// Engine owns the receiver and everything it persists.
type Engine struct {
	emitter     event.EventEmitter
	server      *syslog.SyslogServer
	tlsManager  *pki.TLSManager
	configStore *storage.ConfigStore
	caStore     *storage.PEMStore
	// serverCertStore holds the server's generated TLS identity, so a restart
	// presents the certificate clients were told to trust.
	serverCertStore *storage.PEMStore
	logStore        *storage.LogStore
	simulator       *simulator.Simulator
	dispatcher      *notify.Dispatcher
	secretStore     *storage.SecretStore

	encryptionPassword string // in-memory only for session

	// releaseDir gives the data directory back. openErr is why Open could not
	// claim it: the engine then runs without its database and refuses to
	// receive, so a second process never writes into the first one's files.
	releaseDir func()
	openErr    error
}

// New builds an engine whose configuration, database and keys all live in the
// configuration store's directory. Nothing is read or started until Open.
func New(cs *storage.ConfigStore) *Engine {
	e := &Engine{
		tlsManager:      pki.NewTLSManager(),
		configStore:     cs,
		caStore:         storage.NewCAStore(cs.Dir()),
		serverCertStore: storage.NewServerCertStore(cs.Dir()),
		secretStore:     storage.NewSecretStore(cs.Dir()),
	}
	e.tlsManager.SetOnServerCertGenerated(e.persistServerCert)
	return e
}

// ConfigStore is the store the engine persists to. A host running in-process
// shares it rather than opening a second one on the same file: the store
// rewrites the whole file on every save, and two of them would lose each
// other's changes.
func (e *Engine) ConfigStore() *storage.ConfigStore {
	return e.configStore
}

// DataDir is where the engine keeps everything: configuration, database,
// keys.
func (e *Engine) DataDir() string {
	return e.configStore.Dir()
}

// withDBPath fills in the database location when the configuration leaves it
// to the default. The default is the engine's own data directory, not the
// user's: a service keeps its database where its configuration is.
func (e *Engine) withDBPath(cfg models.StorageConfig) models.StorageConfig {
	if cfg.Path == "" && e.DataDir() != "" {
		cfg.Path = storage.DBPathIn(e.DataDir())
	}
	return cfg
}

// Open starts what the engine runs: the receiver (stopped until StartServer),
// the routing, the database, and the persisted rules and certificates.
// Events — new messages, statistics, alerts — go to emitter.
//
// It fails when another process already has the data directory. The engine is
// still usable as far as reading its configuration goes — every method keeps
// working — but it opens no database and StartServer returns the same error,
// so the caller can say what is wrong instead of crashing on it.
func (e *Engine) Open(emitter event.EventEmitter) error {
	e.emitter = emitter
	e.server = syslog.NewSyslogServer(emitter, e.tlsManager)
	e.simulator = simulator.New(emitter)

	// The dispatcher resolves a credential by sink id AND destination, so a
	// stored secret can only be used with the place it was stored against.
	e.dispatcher = notify.NewDispatcher(emitter, func(sinkID string) string {
		if e.secretStore == nil {
			return ""
		}
		for _, sink := range e.configStore.LoadSinks() {
			if sink.ID != sinkID {
				continue
			}
			dest, ok := notify.Destination(sink)
			if !ok {
				return ""
			}
			return e.secretStore.Get(sinkID, dest)
		}
		return ""
	})
	e.server.SetDispatcher(e.dispatcher)
	// A destination the breaker cuts off is persisted as disabled. Leaving it
	// enabled would mean the next restart walks straight back into the flood
	// that caused it, and the operator would be none the wiser.
	e.dispatcher.SetOnTrip(e.persistTrippedSink)
	e.reconfigureNotify()

	release, err := storage.LockDir(e.DataDir())
	if err != nil {
		e.openErr = fmt.Errorf("%w (%s)", err, e.DataDir())
		slog.Warn("data directory already in use; running without a database", "dir", e.DataDir(), "error", err)
		return e.openErr
	}
	e.releaseDir = release

	// Initialize log store
	storageCfg := e.withDBPath(e.configStore.LoadStorage())
	ls, err := storage.NewLogStore(storageCfg, emitter)
	if err != nil {
		slog.Warn("failed to initialize log store, persistence disabled", "error", err)
	} else {
		e.logStore = ls
		e.server.SetLogStore(ls)
	}

	// Restore alert rules
	rules := e.configStore.LoadAlertRules()
	if len(rules) > 0 {
		e.server.AlertManager.SetRules(rules)
		slog.Info("restored alert rules", "count", len(rules))
	}

	// Restore a persisted CA and server identity if they exist and are not
	// encrypted. Encrypted ones are loaded after the database is unlocked.
	if e.caStore != nil && e.caStore.Exists() && !e.caStore.IsEncrypted() {
		if certPEM, keyPEM, err := e.caStore.Load(""); err == nil && len(certPEM) > 0 {
			if err := e.tlsManager.LoadCAMaterial(certPEM, keyPEM); err != nil {
				slog.Warn("failed to load persisted CA", "error", err)
			} else {
				slog.Info("restored persisted CA")
			}
		}
	}
	if e.serverCertStore != nil && e.serverCertStore.Exists() && !e.serverCertStore.IsEncrypted() {
		if err := e.loadPersistedServerCert(); err != nil {
			slog.Warn("failed to load the persisted server certificate", "error", err)
		}
	}
	return nil
}

// OpenError is why Open could not claim the data directory, or nil.
func (e *Engine) OpenError() error {
	return e.openErr
}

// Close stops everything and flushes what is pending: the simulator, the
// routing, the listeners, then the database, last, so nothing received during
// the shutdown is lost on the way.
func (e *Engine) Close() {
	if e.simulator != nil {
		e.simulator.Stop()
	}
	if e.dispatcher != nil {
		e.dispatcher.Close()
	}
	if e.server != nil {
		e.server.Stop()
		e.configStore.SaveAlertRules(e.server.AlertManager.GetRules())
	}
	if e.logStore != nil {
		e.logStore.Close()
	}
	if e.releaseDir != nil {
		e.releaseDir()
		e.releaseDir = nil
	}
}
