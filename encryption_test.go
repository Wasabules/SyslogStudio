package main

import (
	"strings"
	"testing"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
)

// newTestApp builds an App whose configuration lives in a temp directory, so
// tests never touch the real user config.
func newTestApp(t *testing.T) *App {
	t.Helper()
	return &App{configStore: storage.NewConfigStoreAt(t.TempDir())}
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
	err := a.EnableEncryption("attacker chosen pw")
	if err == nil {
		t.Fatal("EnableEncryption re-keyed an already-encrypted store without the current password")
	}
	if !strings.Contains(err.Error(), "already enabled") {
		t.Errorf("unexpected error: %v", err)
	}
	if a.encryptionPassword != "correct horse battery" {
		t.Errorf("session password was overwritten: %q", a.encryptionPassword)
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

	if err := a.ChangeEncryptionPassword("wrong password", "new password"); err == nil {
		t.Fatal("password changed without the correct current password")
	}
	if a.encryptionPassword != "correct horse battery" {
		t.Errorf("session password changed after a failed attempt: %q", a.encryptionPassword)
	}

	if err := a.ChangeEncryptionPassword("correct horse battery", "another good one"); err != nil {
		t.Fatalf("legitimate password change failed: %v", err)
	}
	if a.encryptionPassword != "another good one" {
		t.Errorf("session password not updated: %q", a.encryptionPassword)
	}
}

// Guard the storage defaults the App relies on when no config exists yet.
func TestTestAppUsesIsolatedConfig(t *testing.T) {
	a := newTestApp(t)
	if got := a.configStore.LoadStorage(); got != models.DefaultStorageConfig() {
		t.Errorf("fresh config store returned %+v, want defaults", got)
	}
}
