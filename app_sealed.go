package main

import (
	"errors"
	"log/slog"
	"time"

	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/inbox"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/remote"
)

// --- Driving a service that seals --------------------------------------------
//
// A service installed by someone whose database is encrypted keeps no
// database: it seals what it receives for them (package inbox). The window
// then drives the service for everything but the history, which lives in the
// window's own encrypted database: the listeners, the live view, the rules,
// the routing and the certificates are the service's; the stored messages,
// their search and the encryption are the window's. Once the database is
// unlocked, the window collects the sealed batches into it.

// collectPoll is how often the window looks for sealed batches, besides
// being told when one is written.
const collectPoll = 5 * time.Second

// sealedBackend is the backend of a window driving a service that seals.
type sealedBackend struct {
	*remote.Client
	store *engine.Engine
}

var _ remote.Backend = sealedBackend{}

// Storage: the window's own database.
func (b sealedBackend) IsStorageReady() bool                      { return b.store.IsStorageReady() }
func (b sealedBackend) GetStorageConfig() models.StorageConfig    { return b.store.GetStorageConfig() }
func (b sealedBackend) SetStorageConfig(cfg models.StorageConfig) { b.store.SetStorageConfig(cfg) }
func (b sealedBackend) GetStorageStats() models.StorageStats      { return b.store.GetStorageStats() }
func (b sealedBackend) QueryMessages(opts models.QueryOptions) models.PagedResult {
	return b.store.QueryMessages(opts)
}
func (b sealedBackend) QueryMessageGroups(filter models.FilterCriteria, groupField string) []models.GroupSummary {
	return b.store.QueryMessageGroups(filter, groupField)
}
func (b sealedBackend) CompactDatabase() error { return b.store.CompactDatabase() }
func (b sealedBackend) ClearDatabase() error   { return b.store.ClearDatabase() }

// Reading the stored messages again happens where they are, with the rules of
// the service, which reads what arrives.
func (b sealedBackend) RereadHistory(opts models.RereadOptions) error {
	if opts.Rules == nil {
		opts.Rules = b.Client.GetSourceRules()
	}
	return b.store.RereadHistory(opts)
}
func (b sealedBackend) GetHistoryReread() models.HistoryReread { return b.store.GetHistoryReread() }
func (b sealedBackend) CancelHistoryReread()                   { b.store.CancelHistoryReread() }

// Encryption: the window's own, which protects that database and the key that
// opens what the service seals.
func (b sealedBackend) GetUnlockAttemptsRemaining() int { return b.store.GetUnlockAttemptsRemaining() }
func (b sealedBackend) GetUnlockLockoutSeconds() int    { return b.store.GetUnlockLockoutSeconds() }
func (b sealedBackend) IsEncryptionEnabled() bool       { return b.store.IsEncryptionEnabled() }
func (b sealedBackend) IsEncryptionLocked() bool        { return b.store.IsEncryptionLocked() }
func (b sealedBackend) IsDatabaseLeftClear() bool       { return b.store.IsDatabaseLeftClear() }
func (b sealedBackend) UnlockDatabase(password string) error {
	return b.store.UnlockDatabase(password)
}
func (b sealedBackend) EnableEncryption(password string) error {
	return b.store.EnableEncryption(password)
}
func (b sealedBackend) DisableEncryption(password string) error {
	return b.store.DisableEncryption(password)
}
func (b sealedBackend) ChangeEncryptionPassword(oldPassword, newPassword string) error {
	return b.store.ChangeEncryptionPassword(oldPassword, newPassword)
}
func (b sealedBackend) GetRecoveryKey() models.RecoveryKeyInfo { return b.store.GetRecoveryKey() }
func (b sealedBackend) SetRecoveryKey(pub []byte) (models.RecoveryKeyInfo, error) {
	return b.store.SetRecoveryKey(pub)
}
func (b sealedBackend) RemoveRecoveryKey() error { return b.store.RemoveRecoveryKey() }
func (b sealedBackend) UnlockWithRecoveryKey(keyFile []byte) error {
	return b.store.UnlockWithRecoveryKey(keyFile)
}
func (b sealedBackend) IsUnlockedByRecoveryKey() bool { return b.store.IsUnlockedByRecoveryKey() }
func (b sealedBackend) ResetEncryptionPassword(newPassword string) error {
	return b.store.ResetEncryptionPassword(newPassword)
}

// Backups: of the window's own database.
func (b sealedBackend) GetBackupConfig() models.BackupConfig { return b.store.GetBackupConfig() }
func (b sealedBackend) SetBackupConfig(cfg models.BackupConfig) error {
	return b.store.SetBackupConfig(cfg)
}
func (b sealedBackend) SaveBackupDestination(d models.BackupDestination) (models.BackupDestination, error) {
	return b.store.SaveBackupDestination(d)
}
func (b sealedBackend) DeleteBackupDestination(id string) error {
	return b.store.DeleteBackupDestination(id)
}
func (b sealedBackend) TestBackupDestination(d models.BackupDestination) models.BackupDestinationCheck {
	return b.store.TestBackupDestination(d)
}
func (b sealedBackend) GetBackupStatus() models.BackupStatus { return b.store.GetBackupStatus() }
func (b sealedBackend) ListBackups() models.BackupListing    { return b.store.ListBackups() }
func (b sealedBackend) BackupNow() error                     { return b.store.BackupNow() }
func (b sealedBackend) RestoreBackup(ref models.BackupRef, password string, keyFile []byte) error {
	return b.store.RestoreBackup(ref, password, keyFile)
}

// sealedPair is the connection and the database to collect between, while
// the window drives a service that seals.
func (a *App) sealedPair() (*remote.Client, *engine.Engine) {
	a.link.mu.Lock()
	defer a.link.mu.Unlock()
	if !a.link.sealed {
		return nil, nil
	}
	return a.link.client, a.link.store
}

// pokeCollect makes the collector look now: a batch was written, or the
// database was just unlocked.
func (a *App) pokeCollect() {
	if a.link.collectPoke == nil {
		return
	}
	select {
	case a.link.collectPoke <- struct{}{}:
	default:
	}
}

func (a *App) collectLoop() {
	defer close(a.link.collectDone)
	t := time.NewTicker(collectPoll)
	defer t.Stop()
	for {
		select {
		case <-a.link.stop:
			return
		case <-t.C:
		case <-a.link.collectPoke:
		}
		a.collectInbox()
	}
}

// collectInbox moves what the service sealed into the window's database:
// list, fetch, open, store, and only then tell the service to delete. A
// batch that does not open stays where it is, and the window says why.
func (a *App) collectInbox() {
	c, store := a.sealedPair()
	if c == nil || store == nil || !store.HasInboxKey() {
		return
	}
	collected, unreadable := 0, ""
	for {
		batches, err := c.InboxBatches()
		if err != nil {
			a.setCollectError(err.Error())
			return
		}
		progress := false
		for _, b := range batches {
			data, err := c.InboxBatch(b.ID)
			if err != nil {
				a.setCollectError(err.Error())
				return
			}
			msgs, err := store.OpenInboxBatch(data)
			if err != nil {
				var other *inbox.OtherKeyError
				if errors.As(err, &other) {
					unreadable = "some batches are sealed for another key than this window's, and stay in the service's inbox"
				} else {
					unreadable = err.Error()
				}
				slog.Warn("a sealed batch could not be opened", "batch", b.ID, "error", err)
				continue
			}
			if err := store.StoreCollected(msgs); err != nil {
				a.setCollectError(err.Error())
				return
			}
			if err := c.InboxAck(b.ID); err != nil {
				a.setCollectError(err.Error())
				return
			}
			collected += len(msgs)
			progress = true
		}
		if !progress {
			break
		}
	}
	a.setCollectError(unreadable)
	if collected > 0 {
		slog.Info("collected the service's sealed messages", "messages", collected)
		a.emit("inbox:collected")
	}
}

// setCollectError records why collecting fails, empty when it works, and
// tells the window when that changed.
func (a *App) setCollectError(msg string) {
	a.link.mu.Lock()
	changed := a.link.collectErr != msg
	a.link.collectErr = msg
	a.link.mu.Unlock()
	if changed {
		a.emit("service:link")
	}
}
