package engine

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"SyslogStudio/internal/backup"
	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
	"SyslogStudio/internal/vault"
)

const backupPassword = "backup test password"

// openEngine opens an engine on a data directory of its own, with msgs
// stored.
func openEngine(t *testing.T, msgs []models.SyslogMessage) (*Engine, string) {
	t.Helper()
	dir := t.TempDir()
	e := New(storage.NewConfigStoreAt(dir))
	if err := e.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	if len(msgs) > 0 {
		if err := e.StoreCollected(msgs); err != nil {
			t.Fatal(err)
		}
	}
	return e, dir
}

// waitBackup waits for the copy that runs to finish.
func waitBackup(t *testing.T, e *Engine) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for e.GetBackupStatus().Running {
		if time.Now().After(deadline) {
			t.Fatal("the backup did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// backupNow runs BackupNow and waits for it, as the window does, then
// returns the newest copy listed — the first destination's.
func backupNow(t *testing.T, e *Engine) models.BackupFile {
	t.Helper()
	if err := e.BackupNow(); err != nil {
		t.Fatal(err)
	}
	waitBackup(t, e)
	for _, d := range e.GetBackupStatus().Destinations {
		if d.LastError != "" {
			t.Fatalf("the backup to %s failed: %s", d.Name, d.LastError)
		}
	}
	listing := e.ListBackups()
	for _, p := range listing.Problems {
		t.Fatalf("%s could not be listed: %s", p.Name, p.Error)
	}
	for _, f := range listing.Files {
		if !f.SafetyCopy {
			return f
		}
	}
	t.Fatal("no backup listed")
	return models.BackupFile{}
}

// refOf names a listed copy.
func refOf(f models.BackupFile) models.BackupRef {
	if f.Destination == "" {
		return models.BackupRef{Path: f.Path}
	}
	return models.BackupRef{Destination: f.Destination, Name: f.Name}
}

// backupHolds opens the copy at path with cred and says how many messages it
// holds.
func backupHolds(t *testing.T, path string, cred backup.Credentials) (int64, error) {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "opened.db")
	if _, err := backup.Open(path, cred, dst, nil); err != nil {
		return 0, err
	}
	view, err := storage.OpenSnapshot(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()
	n, _, _ := view.Span()
	return n, nil
}

// setBackupDir adds a folder destination, and says the folder.
func setBackupDir(t *testing.T, e *Engine) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "backups")
	if _, err := e.SaveBackupDestination(models.BackupDestination{Name: "disk", Kind: models.BackupToFolder, Enabled: true, Path: dir}); err != nil {
		t.Fatal(err)
	}
	return dir
}

// An encrypted database's copy is encrypted as it is, and opens on its own:
// with the password, or with the recovery key — not with anything else.
func TestBackup_EncryptedOpensWithPasswordOrRecoveryKey(t *testing.T) {
	e, _ := openEngine(t, compatMessages())
	if err := e.EnableEncryption(backupPassword); err != nil {
		t.Fatal(err)
	}
	keyFile, pub, _, err := vault.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.SetRecoveryKey(pub); err != nil {
		t.Fatal(err)
	}
	setBackupDir(t, e)
	if lock := e.GetBackupStatus().Lock; lock != models.BackupLockBoth {
		t.Fatalf("the next backup is said to be locked %q", lock)
	}
	f := backupNow(t, e)
	if f.Lock != models.BackupLockBoth || filepath.Ext(f.Path) != backup.Ext || f.KeyID != vault.KeyID(pub) {
		t.Fatalf("backup %+v", f)
	}
	for name, cred := range map[string]backup.Credentials{
		"password": {Password: backupPassword}, "recovery key": {KeyFile: keyFile},
	} {
		n, err := backupHolds(t, f.Path, cred)
		if err != nil || n != 50 {
			t.Errorf("with the %s: %d messages (%v)", name, n, err)
		}
	}
	if _, err := backupHolds(t, f.Path, backup.Credentials{Password: "not the password"}); !errors.Is(err, backup.ErrWrongCredentials) {
		t.Errorf("a wrong password: %v", err)
	}
	otherKey, _, _, _ := vault.GenerateRecoveryKey()
	if _, err := backupHolds(t, f.Path, backup.Credentials{KeyFile: otherKey}); !errors.Is(err, backup.ErrWrongCredentials) {
		t.Errorf("another recovery key: %v", err)
	}
	// Nothing of the database in the clear is left behind.
	if _, err := os.Stat(filepath.Join(e.DataDir(), snapshotFile)); !os.IsNotExist(err) {
		t.Error("the snapshot was left in the data directory")
	}
}

// A copy keeps the locks it was made with: after a change of password it
// still opens with the password it had, and the new one does not open it.
func TestBackup_KeepsThePasswordItWasMadeWith(t *testing.T) {
	e, _ := openEngine(t, compatMessages())
	if err := e.EnableEncryption(backupPassword); err != nil {
		t.Fatal(err)
	}
	setBackupDir(t, e)
	f := backupNow(t, e)
	if err := e.ChangeEncryptionPassword(backupPassword, "the next password"); err != nil {
		t.Fatal(err)
	}
	if n, err := backupHolds(t, f.Path, backup.Credentials{Password: backupPassword}); err != nil || n != 50 {
		t.Errorf("with the password of the day: %d messages (%v)", n, err)
	}
	if _, err := backupHolds(t, f.Path, backup.Credentials{Password: "the next password"}); err == nil {
		t.Error("a later password opens an earlier backup")
	}
}

// A database in the clear is copied locked to the recovery key if there is
// one, in the clear otherwise.
func TestBackup_DatabaseInTheClear(t *testing.T) {
	e, _ := openEngine(t, compatMessages())
	setBackupDir(t, e)
	f := backupNow(t, e)
	if f.Lock != models.BackupLockNone || filepath.Ext(f.Path) != backup.PlainExt {
		t.Fatalf("backup %+v", f)
	}
	if n, err := backupHolds(t, f.Path, backup.Credentials{}); err != nil || n != 50 {
		t.Errorf("the copy in the clear: %d messages (%v)", n, err)
	}

	keyFile, pub, _, _ := vault.GenerateRecoveryKey()
	if _, err := e.SetRecoveryKey(pub); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // a name to the second
	f = backupNow(t, e)
	if f.Lock != models.BackupLockKey {
		t.Fatalf("with a recovery key, the copy is locked %q", f.Lock)
	}
	if n, err := backupHolds(t, f.Path, backup.Credentials{KeyFile: keyFile}); err != nil || n != 50 {
		t.Errorf("with the recovery key: %d messages (%v)", n, err)
	}
	if _, err := backupHolds(t, f.Path, backup.Credentials{Password: "anything"}); err == nil {
		t.Error("a copy locked to the recovery key alone opened with a password")
	}
}

// Restoring puts the copy's database in place, after copying the database
// as it was: the restore can be undone. A wrong password changes nothing.
func TestBackup_RestoreKeepsASafetyCopy(t *testing.T) {
	msgs := compatMessages()
	e, _ := openEngine(t, msgs[:30])
	if err := e.EnableEncryption(backupPassword); err != nil {
		t.Fatal(err)
	}
	setBackupDir(t, e)
	f := backupNow(t, e)
	if err := e.StoreCollected(msgs[30:]); err != nil {
		t.Fatal(err)
	}

	if err := e.RestoreBackup(refOf(f), "not the password", nil); err == nil {
		t.Fatal("a restore went ahead with a wrong password")
	}
	if n, _, _ := e.logStore.Span(); n != 50 {
		t.Fatalf("a refused restore changed the database: %d messages", n)
	}

	if err := e.RestoreBackup(refOf(f), backupPassword, nil); err != nil {
		t.Fatal(err)
	}
	e.logStore.WaitReady()
	if n, _, _ := e.logStore.Span(); n != 30 {
		t.Fatalf("after the restore the database holds %d messages, want the backup's 30", n)
	}
	files := e.ListBackups().Files
	var safety *models.BackupFile
	for i := range files {
		if files[i].SafetyCopy {
			safety = &files[i]
		}
	}
	if safety == nil {
		t.Fatal("no copy of the database was made before the restore")
	}
	if n, err := backupHolds(t, safety.Path, backup.Credentials{Password: backupPassword}); err != nil || n != 50 {
		t.Errorf("the safety copy holds %d messages (%v), want the 50 the database had", n, err)
	}

	// The restored database receives, and is encrypted when it closes.
	e.logStore.BufferMessage(msgs[40])
	deadline := time.Now().Add(30 * time.Second) // polled: generous for a loaded CI under -race
	for {
		if n, _, _ := e.logStore.Span(); n == 31 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a message received after the restore was not written")
		}
		time.Sleep(20 * time.Millisecond)
	}
	e.Close()
	if !vault.IsVaultFile(storage.DBPathIn(e.DataDir()) + ".enc") {
		t.Fatal("the restored database was not encrypted on closing")
	}
}

// A copy owed by the schedule is made up once the application runs again —
// once the database is unlocked — and one that failed to a destination is
// retried an hour later, for that destination.
func TestBackup_ScheduleCatchesUp(t *testing.T) {
	e, _ := openEngine(t, nil)
	setBackupDir(t, e)
	id := e.GetBackupConfig().Destinations[0].ID
	if err := e.SetBackupConfig(models.BackupConfig{Enabled: true, Schedule: models.CleanupSchedule{Every: models.CleanupDaily, At: "03:00"}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	prev := storage.PreviousRun(e.GetBackupConfig().Schedule, now)
	at := func(d time.Duration) string { return prev.Add(d).Format(time.RFC3339) }
	due := func(e *Engine) bool { return len(e.dueDestinations(now)) > 0 }
	set := func(ds destState) {
		e.updateBackupState(func(st *backupState) {
			st.Since = at(-48 * time.Hour)
			st.Destinations[id] = ds
		})
	}

	if due(e) {
		t.Error("a schedule just set owes a backup at once")
	}
	set(destState{})
	if !due(e) {
		t.Error("a missed backup is not made up")
	}
	set(destState{Since: at(time.Minute)})
	if due(e) {
		t.Error("a destination added after the run owes it")
	}
	set(destState{LastAt: at(time.Minute)})
	if due(e) {
		t.Error("a backup already made is owed again")
	}
	set(destState{LastFailAt: now.Add(-10 * time.Minute).Format(time.RFC3339)})
	if due(e) && now.Sub(prev) > 10*time.Minute {
		t.Error("a failed backup is retried at once")
	}
	set(destState{LastFailAt: now.Add(-2 * time.Hour).Format(time.RFC3339)})
	if now.Sub(prev) > 2*time.Hour && !due(e) {
		t.Error("a failed backup is not retried an hour later")
	}

	set(destState{})
	if err := e.EnableEncryption(backupPassword); err != nil {
		t.Fatal(err)
	}
	e.Close()
	locked := New(storage.NewConfigStoreAt(e.DataDir()))
	if err := locked.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	defer locked.Close()
	if due(locked) {
		t.Error("a locked database owes a backup")
	}
	if err := locked.UnlockDatabase(backupPassword); err != nil {
		t.Fatal(err)
	}
	if !due(locked) {
		t.Error("the missed backup is not owed once the database is unlocked")
	}
}

// A folder the backups cannot be written to is refused when it is chosen,
// not discovered at the first scheduled run.
func TestBackup_UnwritableFolderIsRefused(t *testing.T) {
	e, _ := openEngine(t, nil)
	file := filepath.Join(t.TempDir(), "a file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	folder := func(path string) models.BackupDestination {
		return models.BackupDestination{Kind: models.BackupToFolder, Enabled: true, Path: path}
	}
	if _, err := e.SaveBackupDestination(folder(file)); err == nil {
		t.Error("a file was accepted as the backup folder")
	}
	if _, err := e.SaveBackupDestination(folder("relative/dir")); err == nil {
		t.Error("a relative folder was accepted")
	}
	if err := e.SetBackupConfig(models.BackupConfig{Enabled: true}); !errors.Is(err, ErrNoDestination) {
		t.Errorf("backups were turned on with nowhere to go: %v", err)
	}
	if err := e.BackupNow(); !errors.Is(err, ErrNoDestination) {
		t.Errorf("a backup started with nowhere to go: %v", err)
	}
}
