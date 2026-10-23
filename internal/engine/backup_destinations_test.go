package engine

import (
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	ftpserver "github.com/fclairamb/ftpserverlib"
	"github.com/spf13/afero"

	"SyslogStudio/internal/backup"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/notify"
	"SyslogStudio/internal/storage"
)

const ftpPassword = "ftp server password"

type testFTP struct{ dir string }

func (d *testFTP) GetSettings() (*ftpserver.Settings, error) {
	return &ftpserver.Settings{ListenAddr: "127.0.0.1:0"}, nil
}
func (d *testFTP) ClientConnected(ftpserver.ClientContext) (string, error) { return "test", nil }
func (d *testFTP) ClientDisconnected(ftpserver.ClientContext)              {}
func (d *testFTP) GetTLSConfig() (*tls.Config, error)                      { return nil, errors.New("no TLS") }
func (d *testFTP) AuthUser(_ ftpserver.ClientContext, user, pass string) (ftpserver.ClientDriver, error) {
	if user == "backup" && pass == ftpPassword {
		return afero.NewBasePathFs(afero.NewOsFs(), d.dir), nil
	}
	return nil, errors.New("denied")
}

// startFTP runs an FTP server in the clear, and says the destination that
// reaches it, credential included.
func startFTP(t *testing.T) (models.BackupDestination, string) {
	t.Helper()
	dir := t.TempDir()
	srv := ftpserver.NewFtpServer(&testFTP{dir: dir})
	if err := srv.Listen(); err != nil {
		t.Fatal(err)
	}
	go srv.Serve()
	t.Cleanup(func() { srv.Stop() })
	host, p, _ := net.SplitHostPort(srv.Addr())
	port, _ := strconv.Atoi(p)
	return models.BackupDestination{
		Name: "old nas", Kind: models.BackupToFTP, Enabled: true, Cleartext: true,
		Host: host, Port: port, User: "backup", Path: "/nightly", Secret: ftpPassword,
	}, dir
}

// A server destination keeps its password write-only, and away from
// config.json; a copy sent to it is listed, opens with what locked it, and
// restores; the window can read it itself.
func TestBackup_ToAServer(t *testing.T) {
	e, dataDir := openEngine(t, compatMessages())
	if err := e.EnableEncryption(backupPassword); err != nil {
		t.Fatal(err)
	}
	d, serverDir := startFTP(t)
	if check := e.TestBackupDestination(d); !check.OK {
		t.Fatalf("the test failed: %+v", check)
	}
	saved, err := e.SaveBackupDestination(d)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Secret != "" || !saved.HasSecret {
		t.Fatalf("saved destination %+v: the password must be on file and never read back", saved)
	}
	if got := e.GetBackupConfig().Destinations[0]; got.Secret != "" || !got.HasSecret {
		t.Fatalf("the settings give the password back: %+v", got)
	}
	raw, _ := os.ReadFile(filepath.Join(dataDir, "config.json"))
	if strings.Contains(string(raw), ftpPassword) {
		t.Fatal("the password was written to config.json")
	}

	f := backupNow(t, e)
	if f.Destination != saved.ID || f.DestinationName != "old nas" || f.Lock != models.BackupLockPassword || f.SizeMB <= 0 {
		t.Fatalf("listed %+v", f)
	}
	if entries, _ := os.ReadDir(filepath.Join(serverDir, "nightly")); len(entries) != 1 {
		t.Fatalf("the server holds %d files, want the backup", len(entries))
	}

	// The window reads it itself, with what BackupDestinationAccess hands it.
	dest, access, err := e.BackupDestinationAccess(saved.ID)
	if err != nil || access.Password != ftpPassword || dest.Secret != "" {
		t.Fatalf("access %+v %+v (%v)", dest, access, err)
	}
	r, size, err := backup.Fetch(t.Context(), dest, access, f.Name)
	if err != nil {
		t.Fatal(err)
	}
	opened := filepath.Join(t.TempDir(), "opened.db")
	_, err = backup.Unseal(r, size, backup.Credentials{Password: backupPassword}, opened, nil)
	r.Close()
	if err != nil {
		t.Fatal(err)
	}
	view, err := storage.OpenSnapshot(opened)
	if err != nil {
		t.Fatal(err)
	}
	if n, _, _ := view.Span(); n != 50 {
		t.Errorf("the backup read from the server holds %d messages", n)
	}
	view.Close()

	if err := e.StoreCollected(compatMessages()[:1]); err != nil {
		t.Fatal(err)
	}
	if err := e.RestoreBackup(refOf(f), backupPassword, nil); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := e.logStore.Span(); n != 50 {
		t.Errorf("restored from the server: %d messages", n)
	}

	// Moved to another server, the password does not follow.
	moved := saved
	moved.Host = "192.0.2.1"
	if _, err := e.SaveBackupDestination(moved); err == nil {
		t.Error("the password followed the destination to another server")
	}
}

// A copy goes to every destination; one that fails does not stop the
// others, and only it is owed a new attempt.
func TestBackup_SeveralDestinations(t *testing.T) {
	e, _ := openEngine(t, compatMessages())
	good := filepath.Join(t.TempDir(), "good")
	bad := filepath.Join(t.TempDir(), "bad")
	for name, dir := range map[string]string{"good": good, "bad": bad} {
		if _, err := e.SaveBackupDestination(models.BackupDestination{Name: name, Kind: models.BackupToFolder, Enabled: true, Path: dir}); err != nil {
			t.Fatal(err)
		}
	}
	// The second disk goes away: its folder becomes a file.
	os.RemoveAll(bad)
	if err := os.WriteFile(bad, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e.BackupNow(); err != nil {
		t.Fatal(err)
	}
	waitBackup(t, e)
	status := map[string]models.BackupDestinationStatus{}
	for _, d := range e.GetBackupStatus().Destinations {
		status[d.Name] = d
	}
	if status["good"].LastAt == "" || status["good"].LastError != "" {
		t.Errorf("the working destination: %+v", status["good"])
	}
	if status["bad"].LastError == "" || status["bad"].LastAt != "" {
		t.Errorf("the failing destination: %+v", status["bad"])
	}
	if files, _ := os.ReadDir(good); len(files) != 1 {
		t.Errorf("the working destination holds %d files", len(files))
	}

	if err := e.SetBackupConfig(models.BackupConfig{Enabled: true, Schedule: models.CleanupSchedule{Every: models.CleanupDaily}}); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	prev := storage.PreviousRun(e.GetBackupConfig().Schedule, now)
	e.updateBackupState(func(st *backupState) {
		st.Since = prev.Add(-48 * time.Hour).Format(time.RFC3339)
		for id, ds := range st.Destinations {
			ds.Since = ""
			if ds.LastAt != "" {
				ds.LastAt = prev.Add(time.Minute).Format(time.RFC3339)
			} else {
				ds.LastFailAt = prev.Add(-2 * time.Hour).Format(time.RFC3339)
			}
			st.Destinations[id] = ds
		}
	})
	due := e.dueDestinations(now)
	if len(due) != 1 || due[0].Name != "bad" {
		t.Errorf("owed a backup: %v, want only the destination that failed", due)
	}
}

// Pruning the routing's credentials leaves the backups' alone.
func TestBackup_CredentialsSurviveTheRouting(t *testing.T) {
	e, _ := openEngine(t, nil)
	d, _ := startFTP(t)
	saved, err := e.SaveBackupDestination(d)
	if err != nil {
		t.Fatal(err)
	}
	sink := notify.SinkConfig{Name: "hook", Kind: notify.SinkWebhook, Webhook: notify.WebhookSinkConfig{URL: "https://example.invalid/h"}}
	if err := e.SaveNotifySink(sink); err != nil {
		t.Fatal(err)
	}
	for _, s := range e.GetNotifySinks() {
		e.DeleteNotifySink(s.ID)
	}
	if a := e.accessFor(saved); a.Password != ftpPassword {
		t.Fatal("deleting a routing destination took the backup destination's password")
	}
}

// The single folder of the first version of backups becomes a destination,
// with its history.
func TestBackup_TheSingleFolderBecomesADestination(t *testing.T) {
	dir := t.TempDir()
	cs := storage.NewConfigStoreAt(dir)
	folder := filepath.Join(t.TempDir(), "usb")
	cs.SaveBackup(models.BackupConfig{Enabled: true, Dir: folder, Keep: 14, Schedule: models.CleanupSchedule{Every: models.CleanupWeekly}})
	legacy := `{"lastAt": "2026-10-20T03:00:00+02:00", "lastFile": "syslogstudio-20261020-030000.db"}`
	if err := os.WriteFile(filepath.Join(dir, backupStateFile), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	e := New(cs)
	if err := e.Open(nil); err != nil {
		t.Fatal(err)
	}
	defer e.Close()

	cfg := e.GetBackupConfig()
	if len(cfg.Destinations) != 1 || cfg.Dir != "" {
		t.Fatalf("settings %+v", cfg)
	}
	d := cfg.Destinations[0]
	if d.Kind != models.BackupToFolder || d.Path != folder || d.Keep != 14 || !d.Enabled || !cfg.Enabled ||
		cfg.Schedule.Every != models.CleanupWeekly {
		t.Fatalf("destination %+v", d)
	}
	if st := e.GetBackupStatus().Destinations; len(st) != 1 || st[0].LastAt != "2026-10-20T03:00:00+02:00" {
		t.Fatalf("status %+v: the last backup was lost", st)
	}
	if again := e.GetBackupConfig(); len(again.Destinations) != 1 || again.Destinations[0].ID != d.ID {
		t.Fatal("the folder was turned into a destination twice")
	}
}

// Installing the service hands it the backups, credentials included, when
// it keeps a database; a sealing service keeps none, and gets none.
func TestBackup_TheBundleCarriesTheDestinations(t *testing.T) {
	window, _ := openEngine(t, nil)
	d, _ := startFTP(t)
	if _, err := window.SaveBackupDestination(d); err != nil {
		t.Fatal(err)
	}
	b, err := window.ExportBundle()
	if err != nil {
		t.Fatal(err)
	}

	service, _ := openEngine(t, nil)
	if err := service.ImportBundle(b); err != nil {
		t.Fatal(err)
	}
	got := service.GetBackupConfig().Destinations
	if len(got) != 1 || !got[0].HasSecret || service.accessFor(got[0]).Password != ftpPassword {
		t.Fatalf("the service's destinations: %+v", got)
	}
	if check := service.TestBackupDestination(got[0]); !check.OK {
		t.Fatalf("the service cannot reach the destination: %+v", check)
	}

	sealing, _ := openEngine(t, nil)
	pub, err := window.prepareTestInbox(t)
	if err != nil {
		t.Skip("no inbox key: ", err)
	}
	b.InboxPublicKey = pub
	if err := sealing.ImportBundle(b); err != nil {
		t.Fatal(err)
	}
	if got := sealing.GetBackupConfig().Destinations; len(got) != 0 {
		t.Errorf("a sealing service was given backups: %+v", got)
	}
}

// prepareTestInbox makes an inbox key, which wants encryption on.
func (e *Engine) prepareTestInbox(t *testing.T) ([]byte, error) {
	t.Helper()
	if !e.IsEncryptionEnabled() {
		if err := e.EnableEncryption(backupPassword); err != nil {
			return nil, err
		}
	}
	return e.PrepareInbox()
}
