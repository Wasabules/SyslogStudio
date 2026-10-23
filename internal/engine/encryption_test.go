package engine

import (
	"os"
	"strings"
	"testing"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
)

// newTestApp builds an App whose configuration lives in a temp directory, so
// tests never touch the real user config.
func newTestApp(t *testing.T) *Engine {
	t.Helper()
	return New(storage.NewConfigStoreAt(t.TempDir()))
}

func TestEnableEncryption_RejectsWhenAlreadyEnabled(t *testing.T) {
	a := newTestApp(t)

	if err := a.EnableEncryption("correct horse battery"); err != nil {
		t.Fatalf("first EnableEncryption failed: %v", err)
	}
	if !a.configStore.LoadStorage().EncryptionEnabled {
		t.Fatal("encryption not recorded as enabled")
	}

	// A second call must not silently re-key the store: that would be a
	// password change without proof of the current password, and against a
	// still-locked database it would set a password that cannot decrypt the
	// existing logs.db.enc.
	before := a.master
	err := a.EnableEncryption("attacker chosen pw")
	if err == nil {
		t.Fatal("EnableEncryption re-keyed an already-encrypted store without the current password")
	}
	if !strings.Contains(err.Error(), "already enabled") {
		t.Errorf("unexpected error: %v", err)
	}
	if a.master != before || !a.checkPassword("correct horse battery") || a.checkPassword("attacker chosen pw") {
		t.Error("the session was re-keyed by the refused call")
	}
}

func TestEnableEncryption_RejectsShortPassword(t *testing.T) {
	a := newTestApp(t)
	if err := a.EnableEncryption(strings.Repeat("a", minPasswordLen-1)); err == nil {
		t.Fatal("password shorter than the minimum was accepted")
	}
	if a.configStore.LoadStorage().EncryptionEnabled {
		t.Error("encryption enabled despite a rejected password")
	}
}

func TestDisableEncryption_RequiresUnlock(t *testing.T) {
	a := newTestApp(t)
	cfg := a.configStore.LoadStorage()
	cfg.EncryptionEnabled = true
	a.configStore.SaveStorage(cfg)

	// Fresh start, database still locked: no session password is held, so
	// disabling must be refused rather than skipping verification.
	if err := a.DisableEncryption("anything"); err == nil {
		t.Fatal("DisableEncryption succeeded on a locked database")
	}
	if !a.configStore.LoadStorage().EncryptionEnabled {
		t.Error("encryption was disabled despite the refusal")
	}
}

func TestChangeEncryptionPassword_RequiresCurrent(t *testing.T) {
	a := newTestApp(t)
	if err := a.EnableEncryption("correct horse battery"); err != nil {
		t.Fatalf("EnableEncryption failed: %v", err)
	}

	master := a.master
	if err := a.ChangeEncryptionPassword("wrong password", "new password"); err == nil {
		t.Fatal("password changed without the correct current password")
	}
	if a.master != master || !a.checkPassword("correct horse battery") {
		t.Error("the session changed after a failed attempt")
	}

	if err := a.ChangeEncryptionPassword("correct horse battery", "another good one"); err != nil {
		t.Fatalf("legitimate password change failed: %v", err)
	}
	// The new password opens the master secret, the old one no longer does,
	// and nothing had to be encrypted again: the master secret is the same.
	if !a.checkPassword("another good one") || a.checkPassword("correct horse battery") {
		t.Error("the password was not replaced")
	}
	if a.master != master {
		t.Error("a generated master secret was replaced, which needs no rewriting")
	}
}

// Guard the storage defaults the App relies on when no config exists yet.
func TestTestAppUsesIsolatedConfig(t *testing.T) {
	a := newTestApp(t)
	if got := a.configStore.LoadStorage(); got != models.DefaultStorageConfig() {
		t.Errorf("fresh config store returned %+v, want defaults", got)
	}
}

// Turning encryption on handed the database a configuration without its
// path, and closing then encrypted the user's default database instead of
// the engine's own — on a developer's machine, with a test's password.
func TestEncryption_ClosingEncryptsTheEnginesOwnDatabase(t *testing.T) {
	dir := t.TempDir()
	e := New(storage.NewConfigStoreAt(dir))
	if err := e.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	if err := e.EnableEncryption("correct horse battery"); err != nil {
		t.Fatal(err)
	}
	e.Close()

	dbPath := storage.DBPathIn(dir)
	if _, err := os.Stat(dbPath + ".enc"); err != nil {
		t.Fatalf("the engine's database was not encrypted: %v", err)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("the engine's database was left in the clear: %v", err)
	}
	if def, err := storage.ResolveDBPath(""); err == nil {
		if _, err := os.Stat(def + ".enc"); !os.IsNotExist(err) {
			t.Fatalf("the user's default database was written: %s", def)
		}
	}
}

// The storage settings arrive from the window without the encryption flag,
// which only EnableEncryption and DisableEncryption set. Saving them cleared
// it, and the database was then left in the clear when closed.
func TestEncryption_SurvivesAChangeOfStorageSettings(t *testing.T) {
	dir := t.TempDir()
	e := New(storage.NewConfigStoreAt(dir))
	if err := e.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	if err := e.EnableEncryption("correct horse battery"); err != nil {
		t.Fatal(err)
	}
	e.SetStorageConfig(models.StorageConfig{Enabled: true, RetentionDays: 30})
	if !e.GetStorageConfig().EncryptionEnabled {
		t.Error("changing the retention turned encryption off")
	}
	e.Close()
	dbPath := storage.DBPathIn(dir)
	if _, err := os.Stat(dbPath + ".enc"); err != nil {
		t.Fatalf("the database was not encrypted: %v", err)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("the database was left in the clear: %v", err)
	}
}
