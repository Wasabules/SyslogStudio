package engine

// Backups: copies of the database, made on a schedule or on demand, sent to
// every destination the user set up — folders and servers — and restoring
// one. The files and the transports are package backup's; the destinations
// themselves, backup_destinations.go.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"SyslogStudio/internal/backup"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
	"SyslogStudio/internal/updater"
	"SyslogStudio/internal/vault"
)

const (
	// backupTick is how often the schedule is looked at; backupRetry, how
	// long after a failed copy to a destination the next attempt comes — a
	// server back, a disk plugged in again.
	backupTick  = time.Minute
	backupRetry = time.Hour

	backupStateFile = "backup-state.json"
	// snapshotFile and restoreFile are the database in the clear, on its way
	// into a copy or out of one; outgoingDir holds the encrypted copy while it
	// is sent. All in the data directory, beside the database, which is in
	// the clear too while it is open.
	snapshotFile = "backup-snapshot.db"
	restoreFile  = "backup-restore.db"
	outgoingDir  = "backup-outgoing"
	// safetyDir is where the copy made before a restore goes: on this
	// machine, so that undoing a restore never depends on a server.
	safetyDir = "backups"

	// madeKept bounds what is remembered of the copies made here.
	madeKept = 500
)

var (
	// ErrBackupRunning is a copy or a restore asked for while one runs.
	ErrBackupRunning = errors.New("a backup or a restore is already running")
	// ErrNoDestination is a copy asked for with nowhere to send it.
	ErrNoDestination = errors.New("add a destination for the backups first")
)

// backupState is what the copies did, kept across restarts: it is what
// makes up a scheduled copy missed while the application was closed.
type backupState struct {
	// Since is when the schedule was turned on or changed: the runs before
	// it are not owed.
	Since        string               `json:"since,omitempty"`
	Destinations map[string]destState `json:"destinations,omitempty"`
	// Made is what opens each copy made here, by name: a server lists names
	// and sizes, not headers.
	Made map[string]madeInfo `json:"made,omitempty"`

	// The single folder of the first version, read once.
	LastAt     string  `json:"lastAt,omitempty"`
	LastFile   string  `json:"lastFile,omitempty"`
	LastSizeMB float64 `json:"lastSizeMB,omitempty"`
	LastTookMs int64   `json:"lastTookMs,omitempty"`
	LastError  string  `json:"lastError,omitempty"`
	LastFailAt string  `json:"lastFailAt,omitempty"`
}

// destState is how the copies to one destination went.
type destState struct {
	// Since is when the destination was added: the runs before it are not
	// owed to it.
	Since      string  `json:"since,omitempty"`
	LastAt     string  `json:"lastAt,omitempty"`
	LastFile   string  `json:"lastFile,omitempty"`
	LastSizeMB float64 `json:"lastSizeMB,omitempty"`
	LastTookMs int64   `json:"lastTookMs,omitempty"`
	LastError  string  `json:"lastError,omitempty"`
	LastFailAt string  `json:"lastFailAt,omitempty"`
}

type madeInfo struct {
	Lock  string `json:"lock"`
	KeyID string `json:"keyId,omitempty"`
	App   string `json:"app,omitempty"`
}

// backups is the engine's side of the copies: the one that runs, and the
// loop that starts them.
type backups struct {
	mu      sync.Mutex
	running bool
	phase   string
	target  string
	percent float64
	emitted time.Time
	cancel  context.CancelFunc
	// scale maps a step's progress onto a longer operation's: the copy made
	// before a restore.
	scale  func(float64) float64
	closed bool
	stop   chan struct{}
	runs   sync.WaitGroup

	// stateMu serialises the read-modify-write of backup-state.json.
	stateMu sync.Mutex
}

func (e *Engine) backupStatePath() string { return filepath.Join(e.DataDir(), backupStateFile) }

func (e *Engine) loadBackupState() backupState {
	var st backupState
	if data, err := os.ReadFile(e.backupStatePath()); err == nil {
		json.Unmarshal(data, &st)
	}
	if st.Destinations == nil {
		st.Destinations = map[string]destState{}
	}
	if st.Made == nil {
		st.Made = map[string]madeInfo{}
	}
	return st
}

func (e *Engine) saveBackupState(st backupState) {
	data, _ := json.MarshalIndent(st, "", "  ")
	if err := vault.WriteAtomically(e.backupStatePath(), func(w io.Writer) error {
		_, err := w.Write(data)
		return err
	}); err != nil {
		slog.Warn("could not save the backup state", "error", err)
	}
}

// updateBackupState changes the state under its lock.
func (e *Engine) updateBackupState(change func(*backupState)) {
	e.bk.stateMu.Lock()
	defer e.bk.stateMu.Unlock()
	st := e.loadBackupState()
	change(&st)
	e.saveBackupState(st)
}

// backupSchedule is when copies are made: daily unless told otherwise.
func backupSchedule(cfg models.BackupConfig) models.CleanupSchedule {
	s := cfg.Schedule
	if s.Every == models.CleanupContinuous {
		s.Every = models.CleanupDaily
	}
	return s
}

func parseTime(s string) time.Time {
	t, _ := time.Parse(time.RFC3339, s)
	return t
}

func later(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// --- the loop -----------------------------------------------------------------

func (e *Engine) startBackups() {
	e.bk.mu.Lock()
	e.bk.stop = make(chan struct{})
	stop := e.bk.stop
	e.bk.mu.Unlock()
	e.bk.runs.Add(1)
	go func() {
		defer e.bk.runs.Done()
		t := time.NewTicker(backupTick)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case now := <-t.C:
				if due := e.dueDestinations(now); len(due) > 0 {
					e.scheduledBackup(due)
				}
			}
		}
	}()
}

// stopBackups stops the loop and a copy that runs, and waits for both.
func (e *Engine) stopBackups() {
	e.bk.mu.Lock()
	e.bk.closed = true
	if e.bk.cancel != nil {
		e.bk.cancel()
	}
	if e.bk.stop != nil {
		close(e.bk.stop)
		e.bk.stop = nil
	}
	e.bk.mu.Unlock()
	e.bk.runs.Wait()
}

// dueDestinations are the destinations a scheduled copy is owed to: one was
// due since the last that arrived — or since the schedule was set, or the
// destination added — and the last attempt, if it failed, is an hour old. A
// database still locked owes nothing yet: it has not changed since it was
// last open, and it is copied once unlocked.
func (e *Engine) dueDestinations(now time.Time) []models.BackupDestination {
	cfg := e.loadBackupConfig()
	if !cfg.Enabled || e.logStore == nil || e.IsEncryptionLocked() {
		return nil
	}
	prev := storage.PreviousRun(cfg.Schedule, now)
	st := e.loadBackupState()
	var due []models.BackupDestination
	for _, d := range cfg.Destinations {
		if !d.Enabled {
			continue
		}
		ds := st.Destinations[d.ID]
		since := later(later(parseTime(st.Since), parseTime(ds.Since)), parseTime(ds.LastAt))
		if !since.Before(prev) {
			continue
		}
		fail := parseTime(ds.LastFailAt)
		if fail.IsZero() || !fail.After(since) || now.Sub(fail) >= backupRetry {
			due = append(due, d)
		}
	}
	return due
}

func (e *Engine) scheduledBackup(dests []models.BackupDestination) {
	ctx, err := e.beginBackup()
	if err != nil {
		return
	}
	defer e.endBackup()
	e.backupTo(ctx, dests)
}

// BackupNow starts a copy to every enabled destination, and returns once it
// has started: GetBackupStatus and the backup:status event follow it.
func (e *Engine) BackupNow() error {
	var dests []models.BackupDestination
	for _, d := range e.loadBackupConfig().Destinations {
		if d.Enabled {
			dests = append(dests, d)
		}
	}
	if len(dests) == 0 {
		return ErrNoDestination
	}
	if err := e.canBackup(); err != nil {
		return err
	}
	ctx, err := e.beginBackup()
	if err != nil {
		return err
	}
	e.bk.runs.Add(1)
	go func() {
		defer e.bk.runs.Done()
		defer e.endBackup()
		e.backupTo(ctx, dests)
	}()
	return nil
}

func (e *Engine) canBackup() error {
	if e.logStore == nil {
		return errors.New("there is no database to back up: persistence is off")
	}
	if e.IsEncryptionLocked() {
		return errors.New("unlock the database to back it up")
	}
	return nil
}

func (e *Engine) beginBackup() (context.Context, error) {
	e.bk.mu.Lock()
	defer e.bk.mu.Unlock()
	if e.bk.closed {
		return nil, errors.New("the engine is closing")
	}
	if e.bk.running {
		return nil, ErrBackupRunning
	}
	ctx, cancel := context.WithCancel(context.Background())
	e.bk.running, e.bk.cancel = true, cancel
	e.bk.phase, e.bk.target, e.bk.percent = models.BackupPhaseSnapshot, "", 0
	return ctx, nil
}

func (e *Engine) endBackup() {
	e.bk.mu.Lock()
	if e.bk.cancel != nil {
		e.bk.cancel()
	}
	e.bk.running, e.bk.cancel = false, nil
	e.bk.phase, e.bk.target, e.bk.percent = "", "", 0
	e.bk.mu.Unlock()
	e.emitBackupStatus()
}

// progress sets what the running copy is doing, and how far all of it is.
func (e *Engine) progress(phase, target string, percent float64) {
	e.bk.mu.Lock()
	if e.bk.scale != nil {
		percent = e.bk.scale(percent)
	}
	e.bk.phase, e.bk.target, e.bk.percent = phase, target, percent
	emit := time.Since(e.bk.emitted) >= 250*time.Millisecond
	if emit {
		e.bk.emitted = time.Now()
	}
	e.bk.mu.Unlock()
	if emit {
		e.emitBackupStatus()
	}
}

func (e *Engine) emitBackupStatus() {
	if e.emitter != nil {
		e.emitter.Emit("backup:status", e.GetBackupStatus())
	}
}

// --- a copy -------------------------------------------------------------------

// backupLock is what a copy is locked with. An encrypted database's copy has
// its master secret and its locks: it opens with the password of the day,
// or the recovery key. A database in the clear is copied locked to the
// recovery key alone, with a master secret of its own, or in the clear when
// there is no recovery key.
func (e *Engine) backupLock() (backup.Lock, error) {
	k, err := storage.LoadKeyring(e.DataDir())
	if err != nil && !errors.Is(err, storage.ErrNoKeyring) {
		return backup.Lock{}, err
	}
	if e.IsEncryptionEnabled() {
		if e.master == "" {
			return backup.Lock{}, errors.New("unlock the database to back it up")
		}
		if len(k.PasswordSlots()) == 0 {
			return backup.Lock{}, errors.New("the keyring has no password lock: unlock the database again")
		}
		return backup.Lock{Master: e.master, Slots: k.Slots}, nil
	}
	if k.Recovery != nil {
		master := vault.NewMaster()
		slot, err := vault.KeySlot(master, k.Recovery.Public)
		if err != nil {
			return backup.Lock{}, err
		}
		return backup.Lock{Master: master, Slots: []vault.Slot{slot}}, nil
	}
	return backup.Lock{}, nil
}

// nextLock is what the next copy will be locked with, without making it.
func (e *Engine) nextLock() string {
	k, _ := storage.LoadKeyring(e.DataDir())
	switch {
	case e.IsEncryptionEnabled() && len(k.KeySlots()) > 0:
		return models.BackupLockBoth
	case e.IsEncryptionEnabled():
		return models.BackupLockPassword
	case k.Recovery != nil:
		return models.BackupLockKey
	default:
		return models.BackupLockNone
	}
}

// sealSnapshot makes a copy of the database at dst: a snapshot taken while
// messages keep arriving, encrypted, then read back. Its progress runs from
// 0 to 100 of the step it is part of.
func (e *Engine) sealSnapshot(ctx context.Context, dst string, lock backup.Lock) error {
	if err := e.canBackup(); err != nil {
		return err
	}
	snap := filepath.Join(e.DataDir(), snapshotFile)
	removeDB(snap)
	defer removeDB(snap)

	// The snapshot's progress is its size against what the rows take.
	e.progress(models.BackupPhaseSnapshot, "", 0)
	want := max(e.logStore.UsedBytes(), 1)
	done := make(chan struct{})
	go func() {
		t := time.NewTicker(500 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				if fi, err := os.Stat(snap); err == nil {
					e.progress(models.BackupPhaseSnapshot, "", 50*min(1, float64(fi.Size())/float64(want)))
				}
			}
		}
	}()
	err := e.logStore.Snapshot(ctx, snap)
	close(done)
	if err != nil {
		if ctx.Err() != nil {
			err = errors.New("the backup was stopped")
		}
		return fmt.Errorf("copy the database: %w", err)
	}
	encrypt := func(f float64) { e.progress(models.BackupPhaseEncrypt, "", 50+30*f) }
	verify := func(f float64) { e.progress(models.BackupPhaseVerify, "", 80+20*f) }
	if lock.Master == "" {
		encrypt = func(f float64) { e.progress(models.BackupPhaseEncrypt, "", 50+50*f) }
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	return backup.Seal(snap, dst, lock, updater.GetAppVersion(), encrypt, verify)
}

// scaled runs f with the progress of its steps mapped onto [from,
// from+span] of the whole.
func (e *Engine) scaled(from, span float64, f func()) {
	e.bk.mu.Lock()
	outer := e.bk.scale
	e.bk.scale = func(p float64) float64 {
		p = from + span*p/100
		if outer != nil {
			return outer(p)
		}
		return p
	}
	e.bk.mu.Unlock()
	defer func() {
		e.bk.mu.Lock()
		e.bk.scale = outer
		e.bk.mu.Unlock()
	}()
	f()
}

// backupTo makes one copy and sends it to each of dests, recording how it
// went for each: a destination that fails does not stop the others.
func (e *Engine) backupTo(ctx context.Context, dests []models.BackupDestination) {
	start := time.Now()
	fail := func(err error) {
		slog.Warn("backup failed", "error", err)
		now := time.Now().Format(time.RFC3339)
		e.updateBackupState(func(st *backupState) {
			for _, d := range dests {
				ds := st.Destinations[d.ID]
				ds.LastError, ds.LastFailAt = err.Error(), now
				st.Destinations[d.ID] = ds
			}
		})
	}
	lock, err := e.backupLock()
	if err != nil {
		fail(err)
		return
	}
	name := backup.Name(start, false, lock.Master != "")
	local := filepath.Join(e.DataDir(), outgoingDir, name)
	defer os.Remove(local)
	e.scaled(0, 40, func() { err = e.sealSnapshot(ctx, local, lock) })
	if err != nil {
		fail(err)
		return
	}
	size := fileSizeOf(local)
	e.updateBackupState(func(st *backupState) {
		st.Made[name] = madeInfo{Lock: lock.Kind(), KeyID: lock.KeyID(), App: updater.GetAppVersion()}
		trimMade(st.Made)
	})

	span := 60 / float64(len(dests))
	for i, d := range dests {
		if ctx.Err() != nil {
			fail(errors.New("the backup was stopped"))
			return
		}
		from := 40 + span*float64(i)
		sent := time.Now()
		err := e.sendTo(ctx, d, local, name, func(f float64) {
			e.progress(models.BackupPhaseUpload, d.Name, from+span*f)
		})
		now := time.Now().Format(time.RFC3339)
		e.updateBackupState(func(st *backupState) {
			ds := st.Destinations[d.ID]
			if err != nil {
				ds.LastError, ds.LastFailAt = err.Error(), now
			} else {
				ds.LastAt, ds.LastFile, ds.LastSizeMB = now, name, float64(size)/(1<<20)
				ds.LastTookMs = time.Since(start).Milliseconds()
				ds.LastError, ds.LastFailAt = "", ""
			}
			st.Destinations[d.ID] = ds
		})
		if err != nil {
			slog.Warn("backup not sent", "destination", d.Name, "error", err)
		} else {
			slog.Info("backup sent", "destination", d.Name, "file", name, "sizeMB", int(float64(size)/(1<<20)),
				"took", time.Since(sent).Round(time.Millisecond))
		}
	}
}

// sendTo sends the copy at local to d as name, then deletes what d keeps
// beyond its count.
func (e *Engine) sendTo(ctx context.Context, d models.BackupDestination, local, name string, progress backup.Progress) error {
	t, err := backup.Connect(ctx, d, e.accessFor(d))
	if err != nil {
		return describeConnectError(d, err)
	}
	defer t.Close()
	if err := backup.Upload(t, local, name, progress); err != nil {
		return err
	}
	if removed, err := backup.Prune(t, d.Keep); err != nil {
		slog.Warn("old backups could not be deleted", "destination", d.Name, "error", err)
	} else if len(removed) > 0 {
		slog.Info("old backups deleted", "destination", d.Name, "files", removed)
	}
	return nil
}

// describeConnectError says what to do about a server that is not trusted.
func describeConnectError(d models.BackupDestination, err error) error {
	var unknown *backup.UnknownServerError
	var changed *backup.ChangedServerError
	switch {
	case errors.As(err, &unknown):
		return fmt.Errorf("%s is not trusted yet: test it in the backup settings to see its fingerprint", d.Host)
	case errors.As(err, &changed):
		return fmt.Errorf("%s no longer presents the identity it was trusted with (%s instead of %s): refused, someone may be in between", d.Host, changed.Fingerprint, changed.Pinned)
	}
	return err
}

func trimMade(made map[string]madeInfo) {
	if len(made) <= madeKept {
		return
	}
	names := make([]string, 0, len(made))
	for n := range made {
		names = append(names, n)
	}
	// Names sort by date: the oldest go.
	sortStrings(names)
	for _, n := range names[:len(names)-madeKept] {
		delete(made, n)
	}
}

func fileSizeOf(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}

// removeDB removes an SQLite file and what it may have left beside it.
func removeDB(path string) {
	for _, suffix := range []string{"", "-journal", "-wal", "-shm", ".part"} {
		os.Remove(path + suffix)
	}
}

// --- settings and status --------------------------------------------------

// loadBackupConfig reads the backup settings, turning the single folder of
// the first version into a destination the first time.
func (e *Engine) loadBackupConfig() models.BackupConfig {
	cfg := e.configStore.LoadBackup()
	if cfg.Dir != "" && len(cfg.Destinations) == 0 {
		d := models.BackupDestination{
			ID: newID("dest"), Name: filepath.Base(cfg.Dir), Kind: models.BackupToFolder,
			Enabled: true, Keep: cfg.Keep, Path: cfg.Dir,
		}
		cfg.Destinations, cfg.Dir, cfg.Keep = []models.BackupDestination{d}, "", 0
		e.configStore.SaveBackup(cfg)
		e.updateBackupState(func(st *backupState) {
			st.Destinations[d.ID] = destState{
				LastAt: st.LastAt, LastFile: st.LastFile, LastSizeMB: st.LastSizeMB, LastTookMs: st.LastTookMs,
				LastError: st.LastError, LastFailAt: st.LastFailAt,
			}
			st.LastAt, st.LastFile, st.LastSizeMB, st.LastTookMs, st.LastError, st.LastFailAt = "", "", 0, 0, "", ""
		})
	}
	cfg.Schedule = backupSchedule(cfg)
	return cfg
}

// GetBackupConfig is when copies are made, and where they go — the
// destinations without their credentials.
func (e *Engine) GetBackupConfig() models.BackupConfig {
	cfg := e.loadBackupConfig()
	for i := range cfg.Destinations {
		cfg.Destinations[i] = e.forDisplay(cfg.Destinations[i])
	}
	return cfg
}

// SetBackupConfig changes when copies are made. The destinations change
// through SaveBackupDestination and DeleteBackupDestination.
func (e *Engine) SetBackupConfig(next models.BackupConfig) error {
	switch next.Schedule.Every {
	case models.CleanupContinuous, models.CleanupDaily, models.CleanupWeekly, models.CleanupMonthly:
	default:
		return fmt.Errorf("unknown schedule %q", next.Schedule.Every)
	}
	cfg := e.loadBackupConfig()
	if next.Enabled && len(cfg.Destinations) == 0 {
		return ErrNoDestination
	}
	changed := next.Enabled && (!cfg.Enabled || backupSchedule(next) != cfg.Schedule)
	cfg.Enabled, cfg.Schedule = next.Enabled, backupSchedule(next)
	e.configStore.SaveBackup(cfg)
	if changed {
		e.updateBackupState(func(st *backupState) { st.Since = time.Now().Format(time.RFC3339) })
	}
	e.emitBackupStatus()
	return nil
}

// GetBackupStatus says what the copies are doing.
func (e *Engine) GetBackupStatus() models.BackupStatus {
	cfg := e.loadBackupConfig()
	st := e.loadBackupState()
	s := models.BackupStatus{Lock: e.nextLock()}
	for _, d := range cfg.Destinations {
		ds := st.Destinations[d.ID]
		s.Destinations = append(s.Destinations, models.BackupDestinationStatus{
			ID: d.ID, Name: d.Name, LastAt: ds.LastAt, LastFile: ds.LastFile, LastSizeMB: ds.LastSizeMB,
			LastTookMs: ds.LastTookMs, LastError: ds.LastError, LastFailAt: ds.LastFailAt,
		})
	}
	if cfg.Enabled && len(cfg.Destinations) > 0 {
		now := time.Now()
		next := storage.NextRun(cfg.Schedule, now)
		if len(e.dueDestinations(now)) > 0 {
			next = now.Add(backupTick)
		}
		s.Next = next.Format(time.RFC3339)
	}
	e.bk.mu.Lock()
	s.Running, s.Phase, s.Target, s.Percent = e.bk.running, e.bk.phase, e.bk.target, e.bk.percent
	e.bk.mu.Unlock()
	return s
}

// --- restoring ----------------------------------------------------------------

// openSource opens the copy ref names, at a destination or on this machine,
// and says its size if it is known.
func (e *Engine) openSource(ctx context.Context, ref models.BackupRef) (io.ReadCloser, int64, error) {
	if ref.Destination == "" {
		if ref.Path == "" {
			return nil, 0, errors.New("no backup given")
		}
		f, err := os.Open(ref.Path)
		if err != nil {
			return nil, 0, err
		}
		return f, fileSizeOf(ref.Path), nil
	}
	d, ok := e.destination(ref.Destination)
	if !ok {
		return nil, 0, fmt.Errorf("no such destination: %s", ref.Destination)
	}
	r, size, err := backup.Fetch(ctx, d, e.accessFor(d), ref.Name)
	if err != nil {
		return nil, 0, describeConnectError(d, err)
	}
	return r, size, nil
}

// RestoreBackup puts the database a copy holds in place of the database.
// The copy is opened first — a wrong password changes nothing — and the
// database as it is copied, on this machine, before it is replaced: a
// restore can be undone by restoring that one. Messages arriving meanwhile
// are kept, and go to the restored database.
func (e *Engine) RestoreBackup(ref models.BackupRef, password string, keyFile []byte) error {
	if err := e.canBackup(); err != nil {
		return err
	}
	ctx, err := e.beginBackup()
	if err != nil {
		return err
	}
	defer e.endBackup()

	tmp := filepath.Join(e.DataDir(), restoreFile)
	removeDB(tmp)
	defer removeDB(tmp)
	e.progress(models.BackupPhaseOpen, "", 0)
	src, size, err := e.openSource(ctx, ref)
	if err != nil {
		return err
	}
	_, err = backup.Unseal(src, size, backup.Credentials{Password: password, KeyFile: keyFile}, tmp,
		func(f float64) { e.progress(models.BackupPhaseOpen, "", 20*f) })
	src.Close()
	if err != nil {
		return err
	}
	if err := storage.CheckSnapshot(tmp); err != nil {
		return fmt.Errorf("the backup does not hold a usable database: %w", err)
	}

	// What is written from here on is not in the safety copy: it goes over
	// to the restored database.
	mark := e.logStore.Mark()
	lock, err := e.backupLock()
	if err != nil {
		return err
	}
	safety := filepath.Join(e.DataDir(), safetyDir, backup.Name(time.Now(), true, lock.Master != ""))
	e.scaled(20, 70, func() { err = e.sealSnapshot(ctx, safety, lock) })
	if err != nil {
		return fmt.Errorf("the database could not be copied before being replaced, so nothing was restored: %w", err)
	}
	e.updateBackupState(func(st *backupState) {
		st.Made[filepath.Base(safety)] = madeInfo{Lock: lock.Kind(), KeyID: lock.KeyID(), App: updater.GetAppVersion()}
		trimMade(st.Made)
	})
	e.progress(models.BackupPhaseRestore, "", 90)
	if err := e.logStore.Replace(tmp, mark); err != nil {
		return fmt.Errorf("the database could not be replaced; it is as it was: %w", err)
	}
	slog.Info("backup restored", "from", ref, "safetyCopy", safety)
	return nil
}
