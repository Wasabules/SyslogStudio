package main

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"SyslogStudio/internal/backup"
	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/remote"
	"SyslogStudio/internal/storage"
	"SyslogStudio/internal/vault"
)

func historyOf(prefix string, from, n int) []models.SyslogMessage {
	out := make([]models.SyslogMessage, n)
	now := time.Now()
	for i := range out {
		out[i] = models.SyslogMessage{
			ID:         fmt.Sprintf("%s-%05d", prefix, from+i),
			Hostname:   "fw-01",
			Message:    fmt.Sprintf("%s %d", prefix, from+i),
			Timestamp:  now,
			ReceivedAt: now,
		}
	}
	return out
}

// databaseFile writes a database holding msgs at path, as an older copy or
// another installation's would be.
func databaseFile(t *testing.T, path string, msgs []models.SyslogMessage) {
	t.Helper()
	ls, err := storage.NewLogStore(models.StorageConfig{Enabled: true, Path: path}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ls.WaitReady()
	if err := ls.InsertMessages(msgs); err != nil {
		t.Fatal(err)
	}
	ls.Close()
}

// clearService serves an engine storing in the clear in dir, holding msgs,
// and returns a window's connection to it.
func clearService(t *testing.T, dir string, msgs []models.SyslogMessage) (*engine.Engine, *remote.Server, *remote.Client) {
	t.Helper()
	eng := engine.New(storage.NewConfigStoreAt(dir))
	srv := remote.NewServer(eng, "", nil)
	if err := eng.Open(srv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		srv.Close()
		eng.Close()
	})
	if len(msgs) > 0 {
		if _, err := eng.MergeMessages(msgs); err != nil {
			t.Fatal(err)
		}
	}
	window, service := net.Pipe()
	go srv.ServeConn(service)
	c, err := remote.NewClient(window, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return eng, srv, c
}

func storedCount(a *App) int {
	return a.QueryMessages(models.QueryOptions{Page: 1, PageSize: 1}).Total
}

// A backup is merged into the history: what it lacks is added, what it holds
// already stays once. A database file is merged the same way, and an
// encrypted backup opens with its password only.
func TestApp_ImportBackupMergesIntoTheHistory(t *testing.T) {
	a := newAppIn(storage.NewConfigStoreAt(t.TempDir()))
	a.openLocal()
	t.Cleanup(a.stopLink)
	if _, err := a.local().MergeMessages(historyOf("old", 0, 50)); err != nil {
		t.Fatal(err)
	}

	plain := filepath.Join(t.TempDir(), "logs.db")
	databaseFile(t, plain, append(historyOf("old", 30, 20), historyOf("other", 0, 130)...))
	got, err := a.ImportBackup(models.BackupRef{Path: plain}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Kind != copyImport || got.Running || got.Read != 150 || got.Added != 130 || got.Total != 150 {
		t.Fatalf("merging the database file: %+v", got)
	}
	if n := storedCount(a); n != 180 {
		t.Fatalf("the history holds %d messages, want 180", n)
	}
	if _, err := os.Stat(filepath.Join(a.prefs.Dir(), importFile)); !os.IsNotExist(err) {
		t.Fatal("the decrypted copy was left in the data directory")
	}

	// An encrypted backup.
	clear := filepath.Join(t.TempDir(), "clear.db")
	databaseFile(t, clear, historyOf("sealed", 0, 70))
	master := vault.NewMaster()
	slot, err := vault.PasswordSlot(master, "backup password")
	if err != nil {
		t.Fatal(err)
	}
	sealed := filepath.Join(t.TempDir(), "copy"+backup.Ext)
	if err := backup.Seal(clear, sealed, backup.Lock{Master: master, Slots: []vault.Slot{slot}}, "test", nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := a.ImportBackup(models.BackupRef{Path: sealed}, "wrong", ""); err == nil {
		t.Fatal("an encrypted backup was merged with the wrong password")
	}
	if n := storedCount(a); n != 180 {
		t.Fatalf("a refused backup changed the history: %d messages", n)
	}
	if got, err = a.ImportBackup(models.BackupRef{Path: sealed}, "backup password", ""); err != nil || got.Added != 70 {
		t.Fatalf("merging the encrypted backup: %+v, %v", got, err)
	}
	if n := storedCount(a); n != 250 {
		t.Fatalf("the history holds %d messages, want 250", n)
	}
}

// Installing a service that stores in the clear brings the window's history
// to it once the window drives it — and a copy interrupted is taken up where
// it stopped, at the next connection.
func TestApp_HandsItsHistoryToTheServiceItInstalled(t *testing.T) {
	a := newAppIn(storage.NewConfigStoreAt(t.TempDir()))
	a.openLocal()
	t.Cleanup(a.stopLink)
	if _, err := a.local().MergeMessages(historyOf("mine", 0, 410)); err != nil {
		t.Fatal(err)
	}
	db := a.local().GetStorageConfig().Path

	// Stopped after the first 200, at the previous connection.
	snap, err := storage.OpenSnapshot(db)
	if err != nil {
		t.Fatal(err)
	}
	_, cursor, err := snap.MessagesAfter(0, 200)
	snap.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := a.saveHandover(handover{DB: db, Cursor: cursor, Read: 200, Added: 200}); err != nil {
		t.Fatal(err)
	}

	svc, _, c := clearService(t, t.TempDir(), nil)
	a.useService(c, false)
	waitUntil(t, "the history brought over", func() bool {
		c := a.GetHistoryCopy()
		return c.Kind == copyToService && !c.Running
	})
	// Stat, not a read: on Windows, a file this test held open could not be
	// deleted, and the marker would stay for that reason alone.
	waitUntil(t, "the handover marked done", func() bool {
		_, err := os.Stat(a.handoverPath())
		return os.IsNotExist(err)
	})
	if n := svc.GetStorageStats().MessageCount; n != 210 {
		t.Fatalf("the service holds %d messages, want the 210 left to bring", n)
	}
	if got := a.GetHistoryCopy(); got.Kind != copyToService || got.Read != 410 || got.Total != 410 || got.Error != "" {
		t.Fatalf("the copy: %+v", got)
	}
	if n := storedCount(a); n != 210 {
		t.Fatalf("the window shows %d messages of the service's 210", n)
	}
}

// encryptedHistory leaves in dir the window's own database, encrypted, with
// msgs in it.
func encryptedHistory(t *testing.T, dir string, msgs []models.SyslogMessage) {
	t.Helper()
	own := engine.New(storage.NewConfigStoreAt(dir))
	if err := own.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	if err := own.EnableEncryption(sealedPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := own.MergeMessages(msgs); err != nil {
		t.Fatal(err)
	}
	own.Close()
}

// Before the service goes, its history comes back into the window's own
// database — encrypted, opened with its password — which the window then
// drives, unlocked.
func TestApp_TakesTheServiceHistoryBack(t *testing.T) {
	deskDir := t.TempDir()
	encryptedHistory(t, deskDir, historyOf("mine", 0, 30))
	_, srv, c := clearService(t, t.TempDir(), historyOf("service", 0, 260))

	a := newAppIn(storage.NewConfigStoreAt(deskDir))
	t.Cleanup(a.stopLink)
	a.useService(c, false)

	if _, err := a.takeBackHistory("wrong password"); err == nil {
		t.Fatal("the history came back into a database opened with the wrong password")
	}
	a.link.mu.Lock()
	store := a.link.store
	a.link.mu.Unlock()
	if store != nil {
		t.Fatal("a failed copy left the window's engine open")
	}

	if _, err := a.takeBackHistory(sealedPassword); err != nil {
		t.Fatal(err)
	}
	if got := a.GetHistoryCopy(); got.Kind != copyFromService || got.Read != 260 || got.Added != 260 {
		t.Fatalf("the copy: %+v", got)
	}

	// The service is removed: the window drives its own engine, the one the
	// history came back into.
	a.link.mu.Lock()
	a.link.lettingGo = true
	a.link.mu.Unlock()
	srv.Close()
	<-c.Done()
	a.reconnect(c)
	if a.drivingService() || a.local() == nil {
		t.Fatal("the window did not go back to its own engine")
	}
	if a.IsEncryptionLocked() {
		t.Fatal("the window's database is locked again")
	}
	if n := storedCount(a); n != 290 {
		t.Fatalf("the window's database holds %d messages, want 290", n)
	}
}

// When the service stays — the administrator prompt declined — taking the
// history back is undone: the window's engine closes, encrypted again, and
// the window still drives the service.
func TestApp_TakingTheHistoryBackIsUndone(t *testing.T) {
	deskDir := t.TempDir()
	encryptedHistory(t, deskDir, historyOf("mine", 0, 10))
	_, _, c := clearService(t, t.TempDir(), historyOf("service", 0, 20))

	a := newAppIn(storage.NewConfigStoreAt(deskDir))
	t.Cleanup(a.stopLink)
	a.useService(c, false)
	a.elevate = func(args ...string) error { return fmt.Errorf("cancelled") }
	if err := a.UninstallSystemService(false, true, sealedPassword); err == nil {
		t.Fatal("a declined uninstall reported success")
	}
	a.link.mu.Lock()
	store := a.link.store
	a.link.mu.Unlock()
	if store != nil || !a.drivingService() {
		t.Fatal("the window's engine stayed open while the window drives the service")
	}
	if _, err := os.Stat(storage.DBPathIn(deskDir) + ".enc"); err != nil {
		t.Fatalf("the window's database was left decrypted: %v", err)
	}
}

// Encrypting while the window drives a service that stores in the clear: the
// window's database is encrypted, the service seals for it after the
// administrator step, and its history — the database it had — reaches the
// window's database through the inbox, as do its backups.
func TestApp_SealServiceHistory(t *testing.T) {
	deskDir, svcDir := t.TempDir(), t.TempDir()
	a := newAppIn(storage.NewConfigStoreAt(deskDir))
	a.openLocal()
	t.Cleanup(a.stopLink)
	if _, err := a.local().MergeMessages(historyOf("mine", 0, 10)); err != nil {
		t.Fatal(err)
	}

	svc, srv, c := clearService(t, svcDir, historyOf("service", 0, 250))
	backups := t.TempDir()
	if _, err := svc.SaveBackupDestination(models.BackupDestination{Kind: models.BackupToFolder, Path: backups, Keep: 3}); err != nil {
		t.Fatal(err)
	}
	if err := svc.SetBackupConfig(models.BackupConfig{Enabled: true, Schedule: models.CleanupSchedule{Every: models.CleanupDaily, At: "02:30"}}); err != nil {
		t.Fatal(err)
	}
	a.useService(c, false)

	// The administrator step, as sysvc.Seal does it: stop, SealFor, start.
	var sealedSvc *engine.Engine
	var next *remote.Client
	a.elevate = func(args ...string) error {
		if len(args) != 3 || args[0] != "seal" || args[1] != "--inbox-key" {
			return fmt.Errorf("unexpected administrator step %q", args)
		}
		pub, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		srv.Close()
		svc.Close()
		if err := engine.New(storage.NewConfigStoreAt(svcDir)).SealFor(pub); err != nil {
			return err
		}
		sealedSvc = engine.New(storage.NewConfigStoreAt(svcDir))
		srv2 := remote.NewServer(sealedSvc, "", nil)
		if err := sealedSvc.Open(srv2); err != nil {
			return err
		}
		t.Cleanup(func() {
			srv2.Close()
			sealedSvc.Close()
		})
		window, service := net.Pipe()
		go srv2.ServeConn(service)
		next, err = remote.NewClient(window, "", nil)
		return err
	}
	if err := a.SealServiceHistory(sealedPassword); err != nil {
		t.Fatal(err)
	}
	// The watcher would reconnect; here, the test does.
	a.useService(next, false)

	link := a.GetServiceLink()
	if link.Mode != linkService || !link.Sealed {
		t.Fatalf("link: %+v", link)
	}
	if !a.IsEncryptionEnabled() || a.IsEncryptionLocked() {
		t.Fatal("the window's database is not encrypted and open")
	}
	waitUntil(t, "the service's history collected", func() bool {
		a.collectInbox()
		return storedCount(a) == 260
	})
	waitUntil(t, "the service's database in the clear deleted", func() bool {
		_, err := os.Stat(storage.DBPathIn(svcDir))
		return os.IsNotExist(err)
	})
	cfg := a.GetBackupConfig()
	if len(cfg.Destinations) != 1 || cfg.Destinations[0].Path != backups || !cfg.Enabled || cfg.Schedule.At != "02:30" {
		t.Fatalf("the service's backups were not taken over: %+v", cfg)
	}

	a.stopLink()
	if _, err := os.Stat(storage.DBPathIn(deskDir) + ".enc"); err != nil {
		t.Fatalf("the window's database was not encrypted at closing: %v", err)
	}
}
