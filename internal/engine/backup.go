package engine

// Backups: copies of the database to a folder of the user's choosing, on a
// schedule or on demand, and restoring one (the files themselves: package
// backup).

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
	// long after a failed copy the next attempt comes — a network share back,
	// a disk plugged in again.
	backupTick  = time.Minute
	backupRetry = time.Hour

	backupStateFile = "backup-state.json"
	// snapshotFile and restoreFile are the database in the clear, on its way
	// into a copy or out of one: in the data directory, beside the database,
	// which is in the clear too while it is open.
	snapshotFile = "backup-snapshot.db"
	restoreFile  = "backup-restore.db"
	// safetyDir is where the copy made before a restore goes when no backup
	// folder is set.
	safetyDir = "backups"
)

var (
	// ErrBackupRunning is a copy or a restore asked for while one runs.
	ErrBackupRunning = errors.New("a backup or a restore is already running")
	// ErrNoBackupDir is a copy asked for before a folder is chosen.
	ErrNoBackupDir = errors.New("choose a folder for the backups first")
)

// backupState is what the copies did, kept across restarts: it is what
// makes up a scheduled copy missed while the application was closed.
type backupState struct {
	// Since is when the schedule was turned on or changed: the runs before
	// it are not owed.
	Since      string  `json:"since,omitempty"`
	LastAt     string  `json:"lastAt,omitempty"`
	LastFile   string  `json:"lastFile,omitempty"`
	LastSizeMB float64 `json:"lastSizeMB,omitempty"`
	LastTookMs int64   `json:"lastTookMs,omitempty"`
	LastError  string  `json:"lastError,omitempty"`
	LastFailAt string  `json:"lastFailAt,omitempty"`
}

// backups is the engine's side of the copies: the one that runs, and the
// loop that starts them.
type backups struct {
	mu      sync.Mutex
	running bool
	phase   string
	percent float64
	emitted time.Time
	cancel  context.CancelFunc
	// scale maps a copy's progress onto a longer operation's: the copy made
	// before a restore.
	scale  func(float64) float64
	closed bool
	stop   chan struct{}
	runs   sync.WaitGroup
}

func (e *Engine) backupStatePath() string { return filepath.Join(e.DataDir(), backupStateFile) }

func (e *Engine) loadBackupState() backupState {
	var st backupState
	if data, err := os.ReadFile(e.backupStatePath()); err == nil {
		json.Unmarshal(data, &st)
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
				if e.backupDue(now) {
					e.scheduledBackup()
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

// backupDue says whether a scheduled copy is owed: one was due since the
// last that worked — or since the schedule was set — and the last attempt,
// if it failed, is an hour old. A database still locked owes nothing yet:
// it has not changed since it was last open, and it is copied once unlocked.
func (e *Engine) backupDue(now time.Time) bool {
	cfg := e.configStore.LoadBackup()
	if !cfg.Enabled || cfg.Dir == "" || e.logStore == nil || e.IsEncryptionLocked() {
		return false
	}
	st := e.loadBackupState()
	since := parseTime(st.Since)
	if last := parseTime(st.LastAt); last.After(since) {
		since = last
	}
	if !since.Before(storage.PreviousRun(backupSchedule(cfg), now)) {
		return false
	}
	fail := parseTime(st.LastFailAt)
	return fail.IsZero() || !fail.After(since) || now.Sub(fail) >= backupRetry
}

func (e *Engine) scheduledBackup() {
	ctx, err := e.beginBackup()
	if err != nil {
		return
	}
	defer e.endBackup()
	cfg := e.configStore.LoadBackup()
	e.recordBackup(e.writeBackup(ctx, cfg.Dir, false))
	e.pruneBackups(cfg)
}

// BackupNow starts a copy, and returns once it has started: GetBackupStatus
// and the backup:status event follow it.
func (e *Engine) BackupNow() error {
	cfg := e.configStore.LoadBackup()
	if cfg.Dir == "" {
		return ErrNoBackupDir
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
		e.recordBackup(e.writeBackup(ctx, cfg.Dir, false))
		e.pruneBackups(cfg)
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
	e.bk.running, e.bk.cancel, e.bk.phase, e.bk.percent = true, cancel, models.BackupPhaseSnapshot, 0
	return ctx, nil
}

func (e *Engine) endBackup() {
	e.bk.mu.Lock()
	if e.bk.cancel != nil {
		e.bk.cancel()
	}
	e.bk.running, e.bk.cancel, e.bk.phase, e.bk.percent = false, nil, "", 0
	e.bk.mu.Unlock()
	e.emitBackupStatus()
}

// progress sets what the running copy is doing, and how far all of it is.
func (e *Engine) progress(phase string, percent float64) {
	e.bk.mu.Lock()
	if e.bk.scale != nil {
		percent = e.bk.scale(percent)
	}
	e.bk.phase, e.bk.percent = phase, percent
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

func (e *Engine) recordBackup(f models.BackupFile, took time.Duration, err error) {
	st := e.loadBackupState()
	now := time.Now().Format(time.RFC3339)
	if err != nil {
		st.LastError, st.LastFailAt = err.Error(), now
		slog.Warn("backup failed", "error", err)
	} else {
		st.LastAt, st.LastFile, st.LastSizeMB, st.LastTookMs = now, f.Name, f.SizeMB, took.Milliseconds()
		st.LastError, st.LastFailAt = "", ""
		slog.Info("backup written", "file", f.Path, "sizeMB", int(f.SizeMB), "took", took.Round(time.Millisecond))
	}
	e.saveBackupState(st)
}

func (e *Engine) pruneBackups(cfg models.BackupConfig) {
	if removed, err := backup.Prune(cfg.Dir, cfg.Keep); err != nil {
		slog.Warn("old backups could not be deleted", "error", err)
	} else if len(removed) > 0 {
		slog.Info("old backups deleted", "files", removed)
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

// writeBackup copies the database into dir: a snapshot taken while messages
// keep arriving, encrypted into the folder, then read back.
func (e *Engine) writeBackup(ctx context.Context, dir string, safety bool) (models.BackupFile, time.Duration, error) {
	start := time.Now()
	if err := e.canBackup(); err != nil {
		return models.BackupFile{}, 0, err
	}
	lock, err := e.backupLock()
	if err != nil {
		return models.BackupFile{}, 0, err
	}
	snap := filepath.Join(e.DataDir(), snapshotFile)
	removeDB(snap)
	defer removeDB(snap)

	// The snapshot's progress is its size against what the rows take.
	e.progress(models.BackupPhaseSnapshot, 0)
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
					e.progress(models.BackupPhaseSnapshot, 40*min(1, float64(fi.Size())/float64(want)))
				}
			}
		}
	}()
	err = e.logStore.Snapshot(ctx, snap)
	close(done)
	if err != nil {
		if ctx.Err() != nil {
			err = errors.New("the backup was stopped")
		}
		return models.BackupFile{}, 0, fmt.Errorf("copy the database: %w", err)
	}
	encrypt := func(f float64) { e.progress(models.BackupPhaseEncrypt, 40+40*f) }
	verify := func(f float64) { e.progress(models.BackupPhaseVerify, 80+20*f) }
	if lock.Master == "" {
		encrypt = func(f float64) { e.progress(models.BackupPhaseEncrypt, 40+60*f) }
	}
	f, err := backup.Write(snap, dir, start, safety, lock, updater.GetAppVersion(), encrypt, verify)
	if err != nil {
		return f, 0, fmt.Errorf("write the backup to %s: %w", dir, err)
	}
	return f, time.Since(start), nil
}

// removeDB removes an SQLite file and what it may have left beside it.
func removeDB(path string) {
	for _, suffix := range []string{"", "-journal", "-wal", "-shm", ".part"} {
		os.Remove(path + suffix)
	}
}

// --- settings and status --------------------------------------------------

// GetBackupConfig is where copies go, and when.
func (e *Engine) GetBackupConfig() models.BackupConfig {
	cfg := e.configStore.LoadBackup()
	if cfg.Keep < 1 {
		cfg.Keep = models.DefaultBackupKeep
	}
	cfg.Schedule = backupSchedule(cfg)
	return cfg
}

// SetBackupConfig changes it. A folder is checked by writing to it: a
// service's account may not be allowed to, and that is better said now than
// at three in the morning.
func (e *Engine) SetBackupConfig(cfg models.BackupConfig) error {
	if cfg.Dir != "" {
		if !filepath.IsAbs(cfg.Dir) {
			return fmt.Errorf("the backup folder must be a full path")
		}
		if err := checkWritable(cfg.Dir); err != nil {
			return fmt.Errorf("the backups cannot be written to %s: %w", cfg.Dir, err)
		}
	} else if cfg.Enabled {
		return ErrNoBackupDir
	}
	switch cfg.Schedule.Every {
	case models.CleanupContinuous, models.CleanupDaily, models.CleanupWeekly, models.CleanupMonthly:
	default:
		return fmt.Errorf("unknown schedule %q", cfg.Schedule.Every)
	}
	if cfg.Keep < 1 || cfg.Keep > 1000 {
		cfg.Keep = models.DefaultBackupKeep
	}
	cfg.Schedule = backupSchedule(cfg)
	old := e.GetBackupConfig()
	e.configStore.SaveBackup(cfg)
	if cfg.Enabled && (!old.Enabled || old.Schedule != cfg.Schedule || old.Dir != cfg.Dir) {
		st := e.loadBackupState()
		st.Since = time.Now().Format(time.RFC3339)
		e.saveBackupState(st)
	}
	e.emitBackupStatus()
	return nil
}

func checkWritable(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".syslogstudio-check-*")
	if err != nil {
		return err
	}
	name := f.Name()
	f.Close()
	return os.Remove(name)
}

// GetBackupStatus says what the copies are doing.
func (e *Engine) GetBackupStatus() models.BackupStatus {
	cfg := e.GetBackupConfig()
	st := e.loadBackupState()
	s := models.BackupStatus{
		LastAt: st.LastAt, LastFile: st.LastFile, LastSizeMB: st.LastSizeMB, LastTookMs: st.LastTookMs,
		LastError: st.LastError, LastFailAt: st.LastFailAt, Lock: e.nextLock(),
	}
	if cfg.Enabled && cfg.Dir != "" {
		now := time.Now()
		next := storage.NextRun(cfg.Schedule, now)
		if e.backupDue(now) {
			next = now.Add(backupTick)
		}
		s.Next = next.Format(time.RFC3339)
	}
	e.bk.mu.Lock()
	s.Running, s.Phase, s.Percent = e.bk.running, e.bk.phase, e.bk.percent
	e.bk.mu.Unlock()
	return s
}

// ListBackups lists the copies in the backup folder, and those made before a
// restore, newest first.
func (e *Engine) ListBackups() ([]models.BackupFile, error) {
	var out []models.BackupFile
	dirs := []string{filepath.Join(e.DataDir(), safetyDir)}
	if cfg := e.GetBackupConfig(); cfg.Dir != "" && filepath.Clean(cfg.Dir) != dirs[0] {
		dirs = append([]string{cfg.Dir}, dirs...)
	}
	for i, dir := range dirs {
		files, err := backup.List(dir)
		if err != nil {
			if i == 0 && len(dirs) == 2 && !errors.Is(err, os.ErrNotExist) {
				return nil, err
			}
			continue
		}
		out = append(out, files...)
	}
	return out, nil
}

// --- restoring ----------------------------------------------------------------

// RestoreBackup puts the database a copy holds in place of the database.
// The copy is opened first — a wrong password changes nothing — and the
// database as it is copied before it is replaced, beside the other copies:
// a restore can be undone by restoring that one. Messages arriving meanwhile
// are kept, and go to the restored database.
func (e *Engine) RestoreBackup(path, password string, keyFile []byte) error {
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
	e.progress(models.BackupPhaseOpen, 0)
	if _, err := backup.Open(path, backup.Credentials{Password: password, KeyFile: keyFile}, tmp,
		func(f float64) { e.progress(models.BackupPhaseOpen, 20*f) }); err != nil {
		return err
	}
	if err := storage.CheckSnapshot(tmp); err != nil {
		return fmt.Errorf("the backup does not hold a usable database: %w", err)
	}

	dir := e.GetBackupConfig().Dir
	if dir == "" {
		dir = filepath.Join(e.DataDir(), safetyDir)
	}
	// What is written from here on is not in the safety copy: it goes over
	// to the restored database.
	mark := e.logStore.Mark()
	// The safety copy's own progress, folded into 20–90 %.
	safety, _, err := e.writeBackupScaled(ctx, dir, 20, 70)
	if err != nil {
		return fmt.Errorf("the database could not be copied before being replaced, so nothing was restored: %w", err)
	}
	e.progress(models.BackupPhaseRestore, 90)
	if err := e.logStore.Replace(tmp, mark); err != nil {
		return fmt.Errorf("the database could not be replaced; it is as it was: %w", err)
	}
	slog.Info("backup restored", "from", path, "safetyCopy", safety.Path)
	return nil
}

// writeBackupScaled is writeBackup with its progress mapped onto [from,
// from+span] of a longer operation.
func (e *Engine) writeBackupScaled(ctx context.Context, dir string, from, span float64) (models.BackupFile, time.Duration, error) {
	e.bk.mu.Lock()
	e.bk.scale = func(p float64) float64 { return from + span*p/100 }
	e.bk.mu.Unlock()
	defer func() {
		e.bk.mu.Lock()
		e.bk.scale = nil
		e.bk.mu.Unlock()
	}()
	return e.writeBackup(ctx, dir, true)
}
