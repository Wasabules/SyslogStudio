package backup

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/vault"
)

func writeSQLite(t *testing.T, path string) {
	t.Helper()
	data := append([]byte("SQLite format 3\x00"), make([]byte, 4096)...)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
}

func folderTarget(t *testing.T, dir string) Target {
	t.Helper()
	tg, err := openFolder(dir)
	if err != nil {
		t.Fatal(err)
	}
	return tg
}

func TestNames(t *testing.T) {
	at := time.Date(2026, 10, 23, 3, 0, 5, 0, time.Local)
	for _, c := range []struct {
		safety, encrypted bool
		want              string
	}{
		{false, true, "syslogstudio-20261023-030005.ssbackup"},
		{true, true, "syslogstudio-20261023-030005-before-restore.ssbackup"},
		{false, false, "syslogstudio-20261023-030005.db"},
	} {
		name := Name(at, c.safety, c.encrypted)
		if name != c.want {
			t.Errorf("Name = %s, want %s", name, c.want)
		}
		got, safety, ok := parseName(name)
		if !ok || !got.Equal(at) || safety != c.safety {
			t.Errorf("parseName(%s) = %v %v %v", name, got, safety, ok)
		}
	}
	for _, name := range []string{"logs.db", "syslogstudio-notadate.ssbackup", "syslogstudio-20261023-030005.zip", "notes.txt"} {
		if IsName(name) {
			t.Errorf("%s was taken for a backup", name)
		}
	}
}

// Pruning deletes the oldest copies beyond the count kept, and nothing else:
// not the copies made before a restore, not files that only sit in the
// folder. What a copy cut short left behind goes once it is old.
func TestPrune(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 10, 1, 3, 0, 0, 0, time.Local)
	for i := 0; i < 5; i++ {
		writeSQLite(t, filepath.Join(dir, Name(base.AddDate(0, 0, i), false, false)))
	}
	writeSQLite(t, filepath.Join(dir, Name(base.AddDate(0, 0, -10), true, false)))
	for _, other := range []string{"holiday.jpg", "logs.db", "syslogstudio-notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, other), []byte("keep me"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	stale := filepath.Join(dir, Name(base, false, true)+partExt)
	fresh := filepath.Join(dir, Name(base.AddDate(0, 0, 9), false, true)+partExt)
	for _, p := range []string{stale, fresh} {
		if err := os.WriteFile(p, []byte("cut short"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-2 * time.Hour)
	os.Chtimes(stale, old, old)

	tg := folderTarget(t, dir)
	removed, err := Prune(tg, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 4 {
		t.Fatalf("removed %v, want the 3 oldest and the stale part", removed)
	}
	files, _ := List(tg)
	var names []string
	for _, f := range files {
		names = append(names, f.Name)
	}
	want := []string{
		Name(base.AddDate(0, 0, 4), false, false),
		Name(base.AddDate(0, 0, 3), false, false),
		Name(base.AddDate(0, 0, -10), true, false),
	}
	if len(names) != len(want) {
		t.Fatalf("left %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("left %v, want %v", names, want)
		}
	}
	for _, other := range []string{"holiday.jpg", "logs.db", "syslogstudio-notes.txt", filepath.Base(fresh)} {
		if _, err := os.Stat(filepath.Join(dir, other)); err != nil {
			t.Errorf("%s was touched: %v", other, err)
		}
	}
}

// A file named like a copy that is not one does not open.
func TestNotABackup(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, Name(time.Now(), false, false))
	if err := os.WriteFile(fake, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(fake, Credentials{}, filepath.Join(dir, "out.db"), nil); err == nil {
		t.Error("a file that is not a backup opened")
	}
	// A vault file that is a database, not a backup, is refused too.
	db := filepath.Join(dir, "logs.db")
	writeSQLite(t, db)
	enc := filepath.Join(dir, Name(time.Now(), false, true))
	if err := vault.EncryptFile(db, enc, vault.NewMaster(), vault.Header{Kind: vault.KindDatabase}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := Describe(enc); err != ErrNotBackup {
		t.Errorf("a database file was described as a backup: %v", err)
	}
}

// Seal encrypts and reads back; the copy says what opens it, and opens.
func TestSealAndOpen(t *testing.T) {
	src := filepath.Join(t.TempDir(), "snap.db")
	writeSQLite(t, src)
	dst := filepath.Join(t.TempDir(), Name(time.Now(), false, true))
	master := vault.NewMaster()
	slot, err := vault.PasswordSlot(master, "pw")
	if err != nil {
		t.Fatal(err)
	}
	var encrypted, verified float64
	if err := Seal(src, dst, Lock{Master: master, Slots: []vault.Slot{slot}}, "test",
		func(p float64) { encrypted = p }, func(p float64) { verified = p }); err != nil {
		t.Fatal(err)
	}
	f, err := Describe(dst)
	if err != nil || f.Lock != models.BackupLockPassword || f.App != "test" || encrypted != 1 || verified != 1 {
		t.Fatalf("described %+v (%v), progress %v %v", f, err, encrypted, verified)
	}
	out := filepath.Join(t.TempDir(), "back.db")
	if _, err := Open(dst, Credentials{Password: "pw"}, out, nil); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(src)
	b, _ := os.ReadFile(out)
	if !bytes.Equal(a, b) {
		t.Error("the backup does not give back what was written")
	}
	if _, err := Open(dst, Credentials{Password: "wrong"}, out, nil); err != ErrWrongCredentials {
		t.Errorf("a wrong password: %v", err)
	}
}
