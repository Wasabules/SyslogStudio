package engine

import (
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
)

// copyDir copies what a running engine has on disk, as a process killed
// mid-session leaves it: the database in the clear, its WAL, the keyring and
// the configuration. Not the engine's lock, which dies with its process.
func copyDir(t *testing.T, from, to string) {
	t.Helper()
	entries, err := os.ReadDir(from)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.IsDir() || e.Name() == "engine.lock" {
			continue
		}
		src, err := os.Open(filepath.Join(from, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		dst, err := os.Create(filepath.Join(to, e.Name()))
		if err != nil {
			src.Close()
			t.Fatal(err)
		}
		_, err = io.Copy(dst, src)
		src.Close()
		dst.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
}

func openAt(t *testing.T, dir string) *Engine {
	t.Helper()
	e := New(storage.NewConfigStoreAt(dir))
	if err := e.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	return e
}

// An encrypted database decrypted by a session that was then killed — a
// crash, a forced stop, the power — was found in the clear at the next start,
// opened without its password, and never encrypted again. It now waits for
// the password, opens as it was, and is encrypted again when closed.
func TestEncryption_LeftInTheClearByAKilledSession(t *testing.T) {
	const password = "correct horse battery"
	at := time.Now().Add(-time.Hour).UTC()
	var msgs []models.SyslogMessage
	for _, id := range []string{"a", "b", "c"} {
		msgs = append(msgs, models.SyslogMessage{ID: id, Timestamp: at, ReceivedAt: at, Severity: models.SevNotice,
			SeverityLabel: "Notice", FacilityLabel: "user", Message: "message " + id, RawMessage: "message " + id,
			SourceIP: "10.0.0.1", Protocol: "UDP"})
	}

	encrypted, _ := openEngine(t, msgs)
	dir := encrypted.DataDir()
	if err := encrypted.EnableEncryption(password); err != nil {
		t.Fatal(err)
	}
	encrypted.Close()

	// Unlocked, then killed: copied while it runs.
	running := openAt(t, dir)
	if err := running.UnlockDatabase(password); err != nil {
		t.Fatal(err)
	}
	crashed := t.TempDir()
	copyDir(t, dir, crashed)
	running.Close()
	dbPath := storage.DBPathIn(crashed)
	if _, err := os.Stat(dbPath + ".enc"); !os.IsNotExist(err) {
		t.Fatalf("the killed session's copy still has its encrypted file: %v", err)
	}

	e := openAt(t, crashed)
	if !e.IsEncryptionLocked() || !e.IsDatabaseLeftClear() {
		t.Fatalf("found in the clear and opened: locked %v, left clear %v", e.IsEncryptionLocked(), e.IsDatabaseLeftClear())
	}
	if err := e.UnlockDatabase("not the password"); err == nil {
		t.Fatal("a wrong password opened it")
	}
	if err := e.UnlockDatabase(password); err != nil {
		t.Fatal(err)
	}
	if e.IsDatabaseLeftClear() {
		t.Error("still said to be left in the clear once unlocked")
	}
	if got := e.QueryMessages(models.QueryOptions{PageSize: 10}).Total; got != len(msgs) {
		t.Fatalf("%d messages after unlocking, want %d", got, len(msgs))
	}
	e.Close()
	if _, err := os.Stat(dbPath + ".enc"); err != nil {
		t.Fatalf("not encrypted again when closed: %v", err)
	}
	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Fatalf("still in the clear after closing: %v", err)
	}

	// And it opens as any encrypted database does.
	again := openAt(t, crashed)
	defer again.Close()
	if !again.IsEncryptionLocked() || again.IsDatabaseLeftClear() {
		t.Fatalf("after closing: locked %v, left clear %v", again.IsEncryptionLocked(), again.IsDatabaseLeftClear())
	}
	if err := again.UnlockDatabase(password); err != nil {
		t.Fatal(err)
	}
	if got := again.QueryMessages(models.QueryOptions{PageSize: 10}).Total; got != len(msgs) {
		t.Fatalf("%d messages at the next unlock, want %d", got, len(msgs))
	}
}

// A database in the clear with encryption off is just a database: it opens.
func TestEncryption_ClearDatabaseWithEncryptionOffOpens(t *testing.T) {
	e, dir := openEngine(t, nil)
	e.Close()
	again := openAt(t, dir)
	defer again.Close()
	if again.IsEncryptionLocked() || again.IsDatabaseLeftClear() {
		t.Fatal("a database never encrypted waits for a password")
	}
}
