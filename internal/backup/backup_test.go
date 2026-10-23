package backup

import (
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
		if _, _, ok := parseName(name); ok {
			t.Errorf("%s was taken for a backup", name)
		}
	}
}

// Pruning deletes the oldest copies beyond the count kept, and nothing else:
// not the copies made before a restore, not files that only sit in the
// folder.
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
	removed, err := Prune(dir, 2)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Fatalf("removed %v, want the 3 oldest", removed)
	}
	files, _ := List(dir)
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
	for _, other := range []string{"holiday.jpg", "logs.db", "syslogstudio-notes.txt"} {
		if _, err := os.Stat(filepath.Join(dir, other)); err != nil {
			t.Errorf("%s was touched: %v", other, err)
		}
	}
}

// A file named like a copy that is not one is not listed as one, and does
// not open.
func TestNotABackup(t *testing.T) {
	dir := t.TempDir()
	fake := filepath.Join(dir, Name(time.Now(), false, false))
	if err := os.WriteFile(fake, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if files, _ := List(dir); len(files) != 0 {
		t.Errorf("listed %v", files)
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

// Write refuses to overwrite, reads back what it wrote, and the lock says
// what opens the copy.
func TestWrite(t *testing.T) {
	src := filepath.Join(t.TempDir(), "snap.db")
	writeSQLite(t, src)
	dir := filepath.Join(t.TempDir(), "out")
	at := time.Now()
	master := vault.NewMaster()
	slot, err := vault.PasswordSlot(master, "pw")
	if err != nil {
		t.Fatal(err)
	}
	lock := Lock{Master: master, Slots: []vault.Slot{slot}}
	var encrypted, verified float64
	f, err := Write(src, dir, at, false, lock, "test", func(p float64) { encrypted = p }, func(p float64) { verified = p })
	if err != nil {
		t.Fatal(err)
	}
	if f.Lock != models.BackupLockPassword || f.App != "test" || encrypted != 1 || verified != 1 {
		t.Errorf("wrote %+v (progress %v %v)", f, encrypted, verified)
	}
	if _, err := Write(src, dir, at, false, lock, "test", nil, nil); err == nil {
		t.Error("a backup was overwritten")
	}
	out := filepath.Join(t.TempDir(), "back.db")
	if _, err := Open(f.Path, Credentials{Password: "pw"}, out, nil); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(src)
	b, _ := os.ReadFile(out)
	if string(a) != string(b) {
		t.Error("the backup does not give back what was written")
	}
}
