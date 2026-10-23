package main

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sync"

	wailsRuntime "github.com/wailsapp/wails/v2/pkg/runtime"

	"SyslogStudio/internal/backup"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
	"SyslogStudio/internal/vault"
)

// --- Backups, from the window ------------------------------------------------
//
// The engine makes the copies and restores them (internal/engine/backup.go).
// The window picks the folders and files, makes the recovery key — so that
// its private half is written only to the file its user chooses — and opens
// a copy to be read. That last one happens here, in the window's own process
// and with its user's rights, whichever engine the window drives: a copy the
// user can read opens, wherever it is, and nothing of it reaches a service.

// viewFile is the copy being read, in the clear, in the window's own data
// directory.
const viewFile = "backup-view.db"

// maxKeyFile bounds what is read as a recovery key file.
const maxKeyFile = 64 << 10

// backupViewer is a copy opened to be read: the History shows it until it
// is closed.
type backupViewer struct {
	mu    sync.Mutex
	store *storage.LogStore
	info  models.BackupView
}

func (a *App) SelectBackupDir() (string, error) {
	return wailsRuntime.OpenDirectoryDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title:                "Choose the backup folder",
		CanCreateDirectories: true,
	})
}

func (a *App) SelectBackupFile() (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Open a backup",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "SyslogStudio backups (*.ssbackup, *.db)", Pattern: "*" + backup.Ext + ";*" + backup.PlainExt},
			{DisplayName: "All Files", Pattern: "*.*"},
		},
	})
}

func (a *App) SelectRecoveryKeyFile() (string, error) {
	return wailsRuntime.OpenFileDialog(a.ctx, wailsRuntime.OpenDialogOptions{
		Title: "Select the recovery key",
		Filters: []wailsRuntime.FileFilter{
			{DisplayName: "Recovery keys (*.key)", Pattern: "*.key"},
			{DisplayName: "All Files", Pattern: "*.*"},
		},
	})
}

func readKeyFile(path string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxKeyFile+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxKeyFile {
		return nil, errors.New("this is not a recovery key file: too large")
	}
	return data, nil
}

// CreateRecoveryKey makes a recovery key, writes it where the user chooses,
// and locks the installation to it. An empty result is a dialog cancelled.
func (a *App) CreateRecoveryKey() (models.RecoveryKeyInfo, error) {
	file, pub, id, err := vault.GenerateRecoveryKey()
	if err != nil {
		return models.RecoveryKeyInfo{}, err
	}
	path, err := wailsRuntime.SaveFileDialog(a.ctx, wailsRuntime.SaveDialogOptions{
		Title:           "Save the recovery key",
		DefaultFilename: "syslogstudio-recovery-" + id + ".key",
		Filters:         []wailsRuntime.FileFilter{{DisplayName: "Recovery keys (*.key)", Pattern: "*.key"}},
	})
	if err != nil || path == "" {
		return models.RecoveryKeyInfo{}, err
	}
	if err := os.WriteFile(path, file, 0o600); err != nil {
		return models.RecoveryKeyInfo{}, err
	}
	info, err := a.Backend.SetRecoveryKey(pub)
	if err != nil {
		// A key that locks nothing would be kept as if it did.
		os.Remove(path)
		return models.RecoveryKeyInfo{}, err
	}
	return info, nil
}

// DescribeBackup says what the file at path is — when it was made, and what
// opens it — before anything is asked for it.
func (a *App) DescribeBackup(path string) (models.BackupFile, error) {
	return backup.Describe(path)
}

// UnlockWithRecoveryKeyFile unlocks with the recovery key in the file at
// path.
func (a *App) UnlockWithRecoveryKeyFile(path string) error {
	data, err := readKeyFile(path)
	if err != nil {
		return err
	}
	return a.UnlockWithRecoveryKey(data)
}

// RestoreBackupFile restores the copy at path, opened with password or the
// recovery key in the file at keyPath.
func (a *App) RestoreBackupFile(path, password, keyPath string) error {
	key, err := readKeyFile(keyPath)
	if err != nil {
		return err
	}
	return a.Backend.RestoreBackup(path, password, key)
}

func (a *App) viewPath() string {
	return filepath.Join(a.prefs.Dir(), viewFile)
}

// OpenBackup opens the copy at path to be read, with password or the
// recovery key in the file at keyPath: the History shows it until
// CloseBackup.
func (a *App) OpenBackup(path, password, keyPath string) (models.BackupView, error) {
	key, err := readKeyFile(keyPath)
	if err != nil {
		return models.BackupView{}, err
	}
	a.CloseBackup()
	dst := a.viewPath()
	os.Remove(dst)
	f, err := backup.Open(path, backup.Credentials{Password: password, KeyFile: key}, dst, func(p float64) {
		if a.ctx != nil {
			wailsRuntime.EventsEmit(a.ctx, "backup:openProgress", p*100)
		}
	})
	if err != nil {
		os.Remove(dst)
		return models.BackupView{}, err
	}
	store, err := storage.OpenSnapshot(dst)
	if err != nil {
		os.Remove(dst)
		return models.BackupView{}, fmt.Errorf("the backup does not hold a usable database: %w", err)
	}
	count, oldest, newest := store.Span()
	info := models.BackupView{
		Open: true, Name: f.Name, Path: path, Created: f.Created,
		Messages: count, Oldest: oldest, Newest: newest,
	}
	a.view.mu.Lock()
	a.view.store, a.view.info = store, info
	a.view.mu.Unlock()
	slog.Info("backup opened for reading", "file", path, "messages", count)
	return info, nil
}

// CloseBackup closes the copy being read, and removes it from the disk.
func (a *App) CloseBackup() {
	a.view.mu.Lock()
	store := a.view.store
	a.view.store, a.view.info = nil, models.BackupView{}
	a.view.mu.Unlock()
	if store != nil {
		store.Close()
	}
	removeView(a.viewPath())
}

func removeView(path string) {
	for _, suffix := range []string{"", "-journal", "-wal", "-shm", ".part"} {
		os.Remove(path + suffix)
	}
}

// GetBackupView is the copy being read, if one is.
func (a *App) GetBackupView() models.BackupView {
	a.view.mu.Lock()
	defer a.view.mu.Unlock()
	return a.view.info
}

func (a *App) viewStore() *storage.LogStore {
	a.view.mu.Lock()
	defer a.view.mu.Unlock()
	return a.view.store
}

// QueryMessages reads the history: the copy being read while one is open.
func (a *App) QueryMessages(opts models.QueryOptions) models.PagedResult {
	if store := a.viewStore(); store != nil {
		return store.QueryMessages(opts)
	}
	return a.Backend.QueryMessages(opts)
}

// QueryMessageGroups groups the history: the copy being read while one is
// open.
func (a *App) QueryMessageGroups(filter models.FilterCriteria, groupField string) []models.GroupSummary {
	if store := a.viewStore(); store != nil {
		return store.QueryGroups(filter, groupField)
	}
	return a.Backend.QueryMessageGroups(filter, groupField)
}
