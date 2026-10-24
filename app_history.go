package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"SyslogStudio/internal/backup"
	"SyslogStudio/internal/history"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/remote"
	"SyslogStudio/internal/storage"
)

// --- One history, wherever it is kept -----------------------------------------
//
// The messages a window shows live in one database: the window's own, or the
// service's while it drives one that stores in the clear. Going from one to
// the other used to leave the history behind — installing the service
// started an empty one, removing it left the service's in a folder only
// administrators read, or deleted it — and a backup could be read or put in
// place of the database, not added to it.
//
// So the history follows, copied with package history: a batch at a time,
// each message known by its id, so that a copy stopped half way is taken up
// again and adds nothing twice.
//
//   - ImportBackup merges a backup, or a database file, into the history.
//   - Installing a service that stores in the clear brings the window's
//     history to it (handOverHistory), in the background once the window
//     drives it, and again at the next start if it was interrupted.
//   - Removing it brings the service's history back first (takeBackHistory).
//
// A service that seals keeps no history of its own: the window's database
// holds it already, and what the service sealed is collected (app_sealed.go).

// The kinds of copy, as the window names them.
const (
	copyImport      = "import"
	copyToService   = "toService"
	copyFromService = "fromService"
)

const (
	// importFile is where a backup being merged is decrypted, in the
	// window's own data directory.
	importFile = "backup-import.db"
	// handoverFile says that the window's history is still to be brought to
	// the service, and how far that got.
	handoverFile = "history-to-service.json"
	// copyReportEvery is how often a copy under way is reported.
	copyReportEvery = 250 * time.Millisecond
)

// errOwnStorageOff is the window's own storage turned off, when messages
// are to go into it.
var errOwnStorageOff = errors.New("this window's own storage is turned off: there is no database to keep the messages in")

// historyCopies is the copy under way, if one is: one at a time.
type historyCopies struct {
	mu      sync.Mutex
	current models.HistoryCopy
}

// historyOwner is the engine that keeps the history the window shows, and its
// backups: the service's, or the window's own — alone, or for a service that
// seals.
type historyOwner interface {
	history.Source
	history.Sink
	BackupDestinationAccess(id string) (models.BackupDestination, models.BackupAccess, error)
}

func (a *App) historyOwner() historyOwner {
	a.link.mu.Lock()
	defer a.link.mu.Unlock()
	switch {
	case a.link.sealed && a.link.store != nil:
		return a.link.store
	case a.link.client != nil:
		return a.link.client
	case a.engine != nil:
		return a.engine
	}
	return nil
}

// GetHistoryCopy is the copy under way, or the last one.
func (a *App) GetHistoryCopy() models.HistoryCopy {
	a.copies.mu.Lock()
	defer a.copies.mu.Unlock()
	return a.copies.current
}

func (a *App) emitCopy() {
	if a.ctx != nil {
		wailsRuntime.EventsEmit(a.ctx, "history:copy", a.GetHistoryCopy())
	}
}

// copyContext ends when the window closes.
func (a *App) copyContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	stop := a.link.stop
	go func() {
		select {
		case <-stop:
			cancel()
		case <-ctx.Done():
		}
	}()
	return ctx, cancel
}

// copyHistory runs one copy, telling the window how it goes; step, if not
// nil, is told after each batch. Only one copy runs at a time.
func (a *App) copyHistory(kind string, total int64, src history.Source, dst history.Sink,
	from history.Progress, step func(history.Progress)) (models.HistoryCopy, error) {
	a.copies.mu.Lock()
	if a.copies.current.Running {
		a.copies.mu.Unlock()
		return models.HistoryCopy{}, errors.New("messages are being copied already: wait until that is done")
	}
	a.copies.current = models.HistoryCopy{Kind: kind, Running: true, Total: total, Read: from.Read, Added: from.Added}
	a.copies.mu.Unlock()
	a.emitCopy()

	ctx, cancel := a.copyContext()
	defer cancel()
	start, reported := time.Now(), time.Now()
	p, err := history.Copy(ctx, src, dst, from, func(p history.Progress) {
		a.copies.mu.Lock()
		a.copies.current.Read, a.copies.current.Added = p.Read, p.Added
		a.copies.mu.Unlock()
		if step != nil {
			step(p)
		}
		if time.Since(reported) >= copyReportEvery {
			reported = time.Now()
			a.emitCopy()
		}
	})

	a.copies.mu.Lock()
	c := &a.copies.current
	c.Running, c.Read, c.Added = false, p.Read, p.Added
	if err != nil {
		c.Error = err.Error()
	}
	out := *c
	a.copies.mu.Unlock()
	a.emitCopy()
	slog.Info("history copied", "kind", kind, "read", p.Read, "added", p.Added,
		"took", time.Since(start).Round(time.Millisecond), "error", err)
	return out, err
}

// --- Merging a backup ---------------------------------------------------------

// ImportBackup adds the messages of the copy ref names to the history —
// those it lacks; what it holds already stays as it is — opened with
// password or the recovery key in the file at keyPath. A database file
// (.db) is merged the same way.
func (a *App) ImportBackup(ref models.BackupRef, password, keyPath string) (models.HistoryCopy, error) {
	key, err := readKeyFile(keyPath)
	if err != nil {
		return models.HistoryCopy{}, err
	}
	owner := a.historyOwner()
	if owner == nil {
		return models.HistoryCopy{}, storage.ErrNotOpen
	}
	dst := filepath.Join(a.prefs.Dir(), importFile)
	removeView(dst)
	defer removeView(dst)
	if _, err := a.fetchBackup(ref, backup.Credentials{Password: password, KeyFile: key}, dst); err != nil {
		return models.HistoryCopy{}, err
	}
	src, err := storage.OpenSnapshot(dst)
	if err != nil {
		return models.HistoryCopy{}, fmt.Errorf("the backup does not hold a usable database: %w", err)
	}
	defer src.Close()
	count, _, _ := src.Span()
	return a.copyHistory(copyImport, count, src, owner, history.Progress{}, nil)
}

// ImportOpenBackup adds the messages of the copy being read to the history.
func (a *App) ImportOpenBackup() (models.HistoryCopy, error) {
	src := a.viewStore()
	if src == nil {
		return models.HistoryCopy{}, errors.New("no backup is open")
	}
	owner := a.historyOwner()
	if owner == nil {
		return models.HistoryCopy{}, storage.ErrNotOpen
	}
	count, _, _ := src.Span()
	return a.copyHistory(copyImport, count, src, owner, history.Progress{}, nil)
}

// --- The window's history, to the service it installs -------------------------

// handover is what is left of bringing the window's history to the service.
type handover struct {
	// DB is the window's database, in the clear.
	DB     string `json:"db"`
	Cursor int64  `json:"cursor"`
	Read   int64  `json:"read"`
	Added  int64  `json:"added"`
}

func (a *App) handoverPath() string {
	return filepath.Join(a.prefs.Dir(), handoverFile)
}

func (a *App) loadHandover() (handover, bool) {
	data, err := os.ReadFile(a.handoverPath())
	if err != nil {
		return handover{}, false
	}
	var h handover
	if json.Unmarshal(data, &h) != nil || h.DB == "" {
		return handover{}, false
	}
	return h, true
}

func (a *App) saveHandover(h handover) error {
	data, err := json.Marshal(h)
	if err != nil {
		return err
	}
	return os.WriteFile(a.handoverPath(), data, 0o600)
}

// handOverHistory brings the window's history to the service c, if that is
// still to do: after installing it, or where it stopped. It runs once the
// window drives the service, and only then — the window's engine is closed,
// its database read as a file.
func (a *App) handOverHistory(c *remote.Client) {
	h, ok := a.loadHandover()
	if !ok {
		return
	}
	src, err := storage.OpenSnapshot(h.DB)
	if err != nil {
		// Gone, or not a database: there is nothing to bring.
		slog.Warn("the history to bring to the service cannot be read", "file", h.DB, "error", err)
		a.dropHandover()
		return
	}
	defer src.Close()
	count, _, _ := src.Span()
	_, err = a.copyHistory(copyToService, count, src, c, history.Progress{Read: h.Read, Added: h.Added, Cursor: h.Cursor},
		func(p history.Progress) {
			h.Cursor, h.Read, h.Added = p.Cursor, p.Read, p.Added
			a.saveHandover(h)
		})
	if err != nil {
		// Taken up again the next time the window drives the service.
		return
	}
	a.dropHandover()
}

// dropHandover forgets the history to bring over. Windows refuses to delete
// a file another handle has open — a second connection reading it, an
// antivirus scanning it — so it is tried again for a moment. A marker left
// behind would only make the next connection read on from where it stood,
// and find nothing new.
func (a *App) dropHandover() {
	var err error
	for range 20 {
		if err = os.Remove(a.handoverPath()); err == nil || errors.Is(err, os.ErrNotExist) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	slog.Warn("the history brought to the service could not be marked done", "error", err)
}

// --- The service's history, back before it goes -------------------------------

// takeBackHistory copies the service's history into the window's own
// database before the service is removed: it returns the window's engine,
// opened for it — and unlocked with password when it is encrypted — which
// becomes the one driven once the service has gone, and undo, which puts
// things back as they were should the service stay.
//
// A service that seals holds no history: what it still has sealed is
// collected instead.
func (a *App) takeBackHistory(password string) (undo func(), err error) {
	nothing := func() {}
	c := a.serviceClient()
	if c == nil {
		return nothing, errors.New("this window is not driving the service, so its messages cannot be read: start it first")
	}
	a.link.mu.Lock()
	sealed, store := a.link.sealed, a.link.store
	a.link.mu.Unlock()
	if sealed {
		if store == nil || store.IsEncryptionLocked() {
			return nothing, errors.New("unlock the database first: what the service still holds sealed is collected into it")
		}
		a.collectInbox()
		return nothing, nil
	}

	// Nothing more arrives while the history is copied: what the service
	// receives from now on would be lost with it.
	listening := c.GetServerStatus().Running
	if listening {
		if err := c.StopServer(); err != nil {
			return nothing, fmt.Errorf("stop the service's listeners first: %w", err)
		}
	}
	resume := func() {
		if listening {
			if err := c.StartServer(c.GetDefaultConfig()); err != nil {
				slog.Warn("could not restart the service's listeners", "error", err)
			}
		}
	}

	own := a.openStore(nil)
	fail := func(err error) (func(), error) {
		own.Close()
		resume()
		return nothing, err
	}
	if err := own.OpenError(); err != nil {
		return fail(err)
	}
	if !own.GetStorageConfig().Enabled {
		return fail(errOwnStorageOff)
	}
	if own.IsEncryptionLocked() {
		if err := own.UnlockDatabase(password); err != nil {
			return fail(err)
		}
	}
	total := c.GetStorageStats().MessageCount
	if _, err := a.copyHistory(copyFromService, total, c, own, history.Progress{}, nil); err != nil {
		return fail(err)
	}

	// The window's engine once the service has gone (openLocal).
	a.link.mu.Lock()
	a.link.store = own
	a.link.mu.Unlock()
	return func() {
		a.link.mu.Lock()
		kept := a.link.store == own && a.link.client == c
		if kept {
			a.link.store = nil
		}
		a.link.mu.Unlock()
		select {
		case <-c.Done():
			// Gone after all: the window drives its own engine, this one.
			return
		default:
		}
		if kept {
			own.Close()
		}
		resume()
	}, nil
}

// GetOwnDatabase describes the window's own database, which the window does
// not show while it drives a service that stores in the clear: whether it
// is encrypted — moving messages into it then takes its password.
func (a *App) GetOwnDatabase() models.OwnDatabase {
	cfg := a.prefs.LoadStorage()
	return models.OwnDatabase{Enabled: cfg.Enabled, Encrypted: cfg.EncryptionEnabled}
}
