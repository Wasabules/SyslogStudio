package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"SyslogStudio/internal/backup"
	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/notify"
	"SyslogStudio/internal/storage"
	"SyslogStudio/internal/vault"
)

// Installations encrypted by earlier versions must keep opening. testdata/compat
// holds real ones — data directories as a given version left them, written by
// that version's own code — and the tests below open each with this version:
// its password unlocks it, its messages, CA, credentials and inbox key are all
// there, and it reopens after this version has written it back.
//
// A new fixture is written, by the code of the version to freeze, with
//
//	SYSLOGSTUDIO_WRITE_COMPAT=testdata/compat/<version> go test -run TestWriteCompatFixture ./internal/engine
//
// and is never rewritten afterwards: it is what that version left on disks.

const compatPassword = "compat fixture password"

// compatManifest is what a fixture holds, for the tests to check.
type compatManifest struct {
	Version     string   `json:"version"`
	Password    string   `json:"password"`
	MessageIDs  []string `json:"messageIds"`
	CASerial    string   `json:"caSerial"`
	SinkID      string   `json:"sinkId"`
	SinkSecret  string   `json:"sinkSecret"`
	InboxPublic []byte   `json:"inboxPublic"`
	// From the vault format on: the recovery key's file, and a backup made
	// of the installation, both beside it in the fixture.
	RecoveryKey string `json:"recoveryKey,omitempty"`
	Backup      string `json:"backup,omitempty"`
}

func compatMessages() []models.SyslogMessage {
	base := time.Date(2026, 10, 20, 8, 0, 0, 0, time.UTC)
	var msgs []models.SyslogMessage
	for i := 0; i < 50; i++ {
		ts := base.Add(time.Duration(i) * time.Minute)
		msgs = append(msgs, models.SyslogMessage{
			ID: fmt.Sprintf("compat-%02d", i), Timestamp: ts, ReceivedAt: ts,
			Severity: models.Severity(i % 8), SeverityLabel: models.SeverityToLabel(models.Severity(i % 8)),
			Facility: models.FacUser, FacilityLabel: models.FacilityToLabel(models.FacUser),
			Hostname: "compat-host", AppName: "compat", Message: fmt.Sprintf("Échec de connexion %d", i),
			RawMessage: fmt.Sprintf("<14>1 %s compat-host compat - - - Échec de connexion %d", ts.Format(time.RFC3339), i),
			SourceIP:   "192.0.2.10", Protocol: "UDP", Version: 1,
		})
	}
	return msgs
}

func TestWriteCompatFixture(t *testing.T) {
	out := os.Getenv("SYSLOGSTUDIO_WRITE_COMPAT")
	if out == "" {
		t.Skip("set SYSLOGSTUDIO_WRITE_COMPAT to the directory to write")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatalf("%s exists: a fixture is never rewritten", out)
	}
	dir := t.TempDir()
	e := New(storage.NewConfigStoreAt(dir))
	if err := e.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	msgs := compatMessages()
	if err := e.StoreCollected(msgs); err != nil {
		t.Fatal(err)
	}
	ca, err := e.GenerateCA(models.DefaultCertOptions())
	if err != nil {
		t.Fatal(err)
	}
	sink := notify.SinkConfig{ID: "sink-compat", Name: "compat", Kind: notify.SinkWebhook, Enabled: false,
		Webhook: notify.WebhookSinkConfig{URL: "https://example.invalid/hook"}, Secret: "compat-token-1234"}
	if err := e.SaveNotifySink(sink); err != nil {
		t.Fatal(err)
	}
	if err := e.EnableEncryption(compatPassword); err != nil {
		t.Fatal(err)
	}
	pub, err := e.PrepareInbox()
	if err != nil {
		t.Fatal(err)
	}
	e.Close()

	m := compatManifest{
		Version: os.Getenv("SYSLOGSTUDIO_COMPAT_VERSION"), Password: compatPassword,
		CASerial: ca.SerialNumber, SinkID: sink.ID, SinkSecret: sink.Secret, InboxPublic: pub,
	}
	for _, msg := range msgs {
		m.MessageIDs = append(m.MessageIDs, msg.ID)
	}
	if err := os.MkdirAll(out, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || name == "lock" || filepath.Ext(name) == ".lock" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(out, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Logf("fixture file %s (%d bytes)", name, len(data))
	}
	manifest, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), append(manifest, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func copyFixture(t *testing.T, version string) (string, compatManifest) {
	t.Helper()
	src := filepath.Join("testdata", "compat", version)
	dir := t.TempDir()
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	var m compatManifest
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(src, ent.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if ent.Name() == "manifest.json" {
			if err := json.Unmarshal(data, &m); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err := os.WriteFile(filepath.Join(dir, ent.Name()), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return dir, m
}

// checkCompat opens a fixture's directory with this version and checks that
// everything the version that wrote it kept is there.
func checkCompat(t *testing.T, dir string, m compatManifest, unlock func(*Engine) error) {
	t.Helper()
	checkCompatAs(t, dir, m, true, unlock)
}

// checkCompatAs is checkCompat for an installation that may have had its
// encryption turned off since.
func checkCompatAs(t *testing.T, dir string, m compatManifest, encrypted bool, unlock func(*Engine) error) {
	t.Helper()
	e := New(storage.NewConfigStoreAt(dir))
	if err := e.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if encrypted && (!e.IsEncryptionEnabled() || !e.IsEncryptionLocked()) {
		t.Fatalf("the %s installation does not open locked", m.Version)
	}
	if !encrypted && (e.IsEncryptionEnabled() || e.IsEncryptionLocked()) {
		t.Fatalf("the %s installation is still encrypted", m.Version)
	}
	if err := unlock(e); err != nil {
		t.Fatalf("the %s installation does not unlock: %v", m.Version, err)
	}
	e.logStore.WaitReady()
	res := e.QueryMessages(models.QueryOptions{Page: 1, PageSize: 500, SortField: "timestamp", SortDir: "asc"})
	if res.Total != len(m.MessageIDs) {
		t.Fatalf("%d messages, want the %d the %s installation held", res.Total, len(m.MessageIDs), m.Version)
	}
	for i, msg := range res.Messages {
		if msg.ID != m.MessageIDs[i] {
			t.Fatalf("message %d is %s, want %s", i, msg.ID, m.MessageIDs[i])
		}
	}
	if ca, err := e.GetCACertInfo(); err != nil || ca.SerialNumber != m.CASerial {
		t.Errorf("the CA is %+v (%v), want serial %s", ca, err, m.CASerial)
	}
	sinks := e.GetNotifySinks()
	if len(sinks) != 1 || !sinks[0].HasSecret {
		t.Fatalf("sinks %+v: the credential is not on file", sinks)
	}
	dest, _ := notify.Destination(sinks[0])
	if got := e.secretStore.Get(m.SinkID, dest); got != m.SinkSecret {
		t.Errorf("the credential reads %q, want %q", got, m.SinkSecret)
	}
	if !e.HasInboxKey() {
		t.Error("the inbox key does not load")
	}
}

// A v1.7.1 installation opens with its password, then again once this
// version has closed it — whatever this version wrote back.
func TestCompat_V171InstallationOpens(t *testing.T) {
	dir, m := copyFixture(t, "v1.7.1")
	byPassword := func(e *Engine) error { return e.UnlockDatabase(m.Password) }
	checkCompat(t, dir, m, byPassword)
	checkCompat(t, dir, m, byPassword)
}

// The same v1.7.1 installation, taken through everything this version adds:
// a recovery key set up, the database reopened with that key alone, a new
// password set without the old one, the old one refused afterwards — and the
// installation whole at every step.
func TestCompat_V171InstallationThroughRecovery(t *testing.T) {
	dir, m := copyFixture(t, "v1.7.1")
	byPassword := func(password string) func(*Engine) error {
		return func(e *Engine) error { return e.UnlockDatabase(password) }
	}
	var keyFile []byte
	checkCompat(t, dir, m, func(e *Engine) error {
		if err := e.UnlockDatabase(m.Password); err != nil {
			return err
		}
		file, pub, _, err := vault.GenerateRecoveryKey()
		if err != nil {
			return err
		}
		keyFile = file
		_, err = e.SetRecoveryKey(pub)
		return err
	})
	if !vault.IsVaultFile(storage.DBPathIn(dir) + ".enc") {
		t.Fatal("the database was not written back in the current format")
	}
	const newPassword = "a brand new password"
	checkCompat(t, dir, m, func(e *Engine) error {
		if err := e.UnlockWithRecoveryKey(keyFile); err != nil {
			return err
		}
		if !e.IsUnlockedByRecoveryKey() {
			t.Error("the session does not say the recovery key opened it")
		}
		return e.ResetEncryptionPassword(newPassword)
	})
	e := New(storage.NewConfigStoreAt(dir))
	if err := e.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	if err := e.UnlockDatabase(m.Password); err == nil {
		t.Fatal("the old password still opens the installation after a reset")
	}
	e.Close()
	e.configStore.SaveLockout(models.LockoutState{})
	checkCompat(t, dir, m, byPassword(newPassword))
	checkCompat(t, dir, m, func(e *Engine) error { return e.UnlockWithRecoveryKey(keyFile) })
}

// A v1.7.1 installation whose password is changed: its master secret, the old
// password itself, is replaced, and everything written under it follows —
// the credentials included, which up to v1.7.1 stayed under the old password.
// Then encryption off and on again, the installation whole each time.
func TestCompat_V171InstallationThroughPasswordChanges(t *testing.T) {
	dir, m := copyFixture(t, "v1.7.1")
	const newPassword = "a brand new password"
	checkCompat(t, dir, m, func(e *Engine) error {
		if err := e.UnlockDatabase(m.Password); err != nil {
			return err
		}
		if err := e.ChangeEncryptionPassword(m.Password, newPassword); err != nil {
			return err
		}
		if !vault.IsGenerated(e.master) {
			t.Error("the password is still the master secret after a change")
		}
		return nil
	})
	byNew := func(e *Engine) error { return e.UnlockDatabase(newPassword) }
	checkCompat(t, dir, m, byNew)
	checkCompat(t, dir, m, func(e *Engine) error {
		if err := byNew(e); err != nil {
			return err
		}
		return e.DisableEncryption(newPassword)
	})
	checkCompatAs(t, dir, m, false, func(e *Engine) error { return nil })
	checkCompatAs(t, dir, m, false, func(e *Engine) error { return e.EnableEncryption(m.Password) })
	checkCompat(t, dir, m, func(e *Engine) error { return e.UnlockDatabase(m.Password) })
}

// A password change on a v1.7.1 installation replaces its master secret, then
// writes every key file again. Interrupted in between — a crash, a full disk —
// some files are left under the old secret: they must still open, and be
// written under the new one then.
func TestCompat_V171InterruptedRotationRecovers(t *testing.T) {
	dir, m := copyFixture(t, "v1.7.1")
	const newPassword = "a brand new password"
	checkCompat(t, dir, m, func(e *Engine) error {
		if err := e.UnlockDatabase(m.Password); err != nil {
			return err
		}
		return e.ChangeEncryptionPassword(m.Password, newPassword)
	})

	// Put back the files as v1.7.1 wrote them, under the old secret, and the
	// old secret in the keyring: what an interrupted rewrite leaves.
	src := filepath.Join("testdata", "compat", "v1.7.1")
	for _, name := range []string{"ca.json.enc", "sinksecrets.json.enc", "inbox-key.json.enc"} {
		data, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	probe := New(storage.NewConfigStoreAt(dir))
	master, _, err := probe.masterFor(newPassword)
	if err != nil {
		t.Fatal(err)
	}
	k, err := storage.LoadKeyring(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(k.Previous) != 0 {
		t.Fatal("the keyring kept the previous master secret after a complete rewrite")
	}
	if err := k.SetPrevious(m.Password, master); err != nil {
		t.Fatal(err)
	}
	if err := storage.SaveKeyring(dir, k); err != nil {
		t.Fatal(err)
	}

	byNew := func(e *Engine) error { return e.UnlockDatabase(newPassword) }
	checkCompat(t, dir, m, byNew)
	if k, _ := storage.LoadKeyring(dir); len(k.Previous) == 0 {
		t.Error("the previous master secret was dropped in the session that still needed it")
	}
	checkCompat(t, dir, m, byNew)
	if k, _ := storage.LoadKeyring(dir); len(k.Previous) != 0 {
		t.Error("the previous master secret is still kept once everything opens with the new one")
	}
	if err := probe.readableWith(master); err != nil {
		t.Errorf("not everything was written under the new master secret: %v", err)
	}
}

// --- the vault format -------------------------------------------------------
//
// testdata/compat/vault-v1 is an installation as the version that brought the
// keyring, the recovery key and backups left it: encrypted, with a recovery
// key, and a backup made of it under backups/. Written once with
//
//	SYSLOGSTUDIO_WRITE_VAULT_COMPAT=testdata/compat/vault-v1 go test -run TestWriteVaultFixture ./internal/engine
//
// and never rewritten: every later version must open the installation, with
// its password and with its recovery key, and open and restore the backup.

const vaultFixture = "vault-v1"

func TestWriteVaultFixture(t *testing.T) {
	out := os.Getenv("SYSLOGSTUDIO_WRITE_VAULT_COMPAT")
	if out == "" {
		t.Skip("set SYSLOGSTUDIO_WRITE_VAULT_COMPAT to the directory to write")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatalf("%s exists: a fixture is never rewritten", out)
	}
	dir := t.TempDir()
	e := New(storage.NewConfigStoreAt(dir))
	if err := e.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	msgs := compatMessages()
	if err := e.StoreCollected(msgs); err != nil {
		t.Fatal(err)
	}
	ca, err := e.GenerateCA(models.DefaultCertOptions())
	if err != nil {
		t.Fatal(err)
	}
	sink := notify.SinkConfig{ID: "sink-compat", Name: "compat", Kind: notify.SinkWebhook, Enabled: false,
		Webhook: notify.WebhookSinkConfig{URL: "https://example.invalid/hook"}, Secret: "compat-token-1234"}
	if err := e.SaveNotifySink(sink); err != nil {
		t.Fatal(err)
	}
	if err := e.EnableEncryption(compatPassword); err != nil {
		t.Fatal(err)
	}
	pub, err := e.PrepareInbox()
	if err != nil {
		t.Fatal(err)
	}
	keyFile, keyPub, _, err := vault.GenerateRecoveryKey()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.SetRecoveryKey(keyPub); err != nil {
		t.Fatal(err)
	}
	backupDir := filepath.Join(t.TempDir(), "backups")
	if err := e.SetBackupConfig(models.BackupConfig{Dir: backupDir}); err != nil {
		t.Fatal(err)
	}
	bk := backupNow(t, e)
	if err := e.SetBackupConfig(models.BackupConfig{}); err != nil {
		t.Fatal(err)
	}
	e.Close()

	m := compatManifest{
		Version: "vault format 1", Password: compatPassword,
		CASerial: ca.SerialNumber, SinkID: sink.ID, SinkSecret: sink.Secret, InboxPublic: pub,
		RecoveryKey: "recovery.key", Backup: bk.Name,
	}
	for _, msg := range msgs {
		m.MessageIDs = append(m.MessageIDs, msg.ID)
	}
	if err := os.MkdirAll(filepath.Join(out, "backups"), 0o755); err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	for _, ent := range entries {
		name := ent.Name()
		if ent.IsDir() || name == "lock" || filepath.Ext(name) == ".lock" || name == backupStateFile {
			continue
		}
		copyFile(t, filepath.Join(dir, name), filepath.Join(out, name))
	}
	copyFile(t, bk.Path, filepath.Join(out, "backups", bk.Name))
	if err := os.WriteFile(filepath.Join(out, m.RecoveryKey), keyFile, 0o644); err != nil {
		t.Fatal(err)
	}
	manifest, _ := json.MarshalIndent(m, "", "  ")
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), append(manifest, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture file %s (%d bytes)", filepath.Base(to), len(data))
}

func fixtureFile(t *testing.T, version string, parts ...string) string {
	t.Helper()
	return filepath.Join(append([]string{"testdata", "compat", version}, parts...)...)
}

func fixtureKey(t *testing.T, version string, m compatManifest) []byte {
	t.Helper()
	key, err := os.ReadFile(fixtureFile(t, version, m.RecoveryKey))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// The installation opens with its password and with its recovery key, again
// and again, whatever this version writes back.
func TestCompat_VaultV1InstallationOpens(t *testing.T) {
	dir, m := copyFixture(t, vaultFixture)
	key := fixtureKey(t, vaultFixture, m)
	byPassword := func(e *Engine) error { return e.UnlockDatabase(m.Password) }
	byKey := func(e *Engine) error { return e.UnlockWithRecoveryKey(key) }
	checkCompat(t, dir, m, byPassword)
	checkCompat(t, dir, m, byKey)
	checkCompat(t, dir, m, byPassword)
	checkCompat(t, dir, m, byKey)
}

// The backup opens on its own, with the password or the recovery key, and
// restores — into the installation it came from, and into another one,
// encrypted with another password, which then keeps it under its own.
func TestCompat_VaultV1BackupOpensAndRestores(t *testing.T) {
	m := loadManifest(t, vaultFixture)
	path := fixtureFile(t, vaultFixture, "backups", m.Backup)
	key := fixtureKey(t, vaultFixture, m)
	for name, cred := range map[string]backup.Credentials{
		"password": {Password: m.Password}, "recovery key": {KeyFile: key},
	} {
		if n, err := backupHolds(t, path, cred); err != nil || n != int64(len(m.MessageIDs)) {
			t.Errorf("the backup opened with the %s holds %d messages (%v), want %d", name, n, err, len(m.MessageIDs))
		}
	}

	dir, _ := copyFixture(t, vaultFixture)
	checkCompat(t, dir, m, func(e *Engine) error {
		if err := e.UnlockDatabase(m.Password); err != nil {
			return err
		}
		return e.RestoreBackup(path, "", key)
	})

	const other = "another installation's password"
	e, otherDir := openEngine(t, nil)
	if err := e.EnableEncryption(other); err != nil {
		t.Fatal(err)
	}
	if err := e.RestoreBackup(path, m.Password, nil); err != nil {
		t.Fatal(err)
	}
	e.Close()
	again := New(storage.NewConfigStoreAt(otherDir))
	if err := again.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if err := again.UnlockDatabase(other); err != nil {
		t.Fatalf("the installation a backup was restored into does not open with its own password: %v", err)
	}
	again.logStore.WaitReady()
	res := again.QueryMessages(models.QueryOptions{Page: 1, PageSize: 500, SortField: "timestamp", SortDir: "asc"})
	if res.Total != len(m.MessageIDs) {
		t.Fatalf("the restored database holds %d messages, want %d", res.Total, len(m.MessageIDs))
	}
	for i, msg := range res.Messages {
		if msg.ID != m.MessageIDs[i] {
			t.Fatalf("restored message %d is %s, want %s", i, msg.ID, m.MessageIDs[i])
		}
	}
}

// An installation encrypted by v1.7.1 is backed up by this version: the
// backup opens with v1.7.1's password, and restores into the installation.
func TestCompat_V171BackupAfterUpgrade(t *testing.T) {
	dir, m := copyFixture(t, "v1.7.1")
	var bk models.BackupFile
	checkCompat(t, dir, m, func(e *Engine) error {
		if err := e.UnlockDatabase(m.Password); err != nil {
			return err
		}
		if err := e.SetBackupConfig(models.BackupConfig{Dir: filepath.Join(t.TempDir(), "backups")}); err != nil {
			return err
		}
		bk = backupNow(t, e)
		return nil
	})
	if n, err := backupHolds(t, bk.Path, backup.Credentials{Password: m.Password}); err != nil || n != int64(len(m.MessageIDs)) {
		t.Fatalf("the backup of a v1.7.1 installation holds %d messages (%v)", n, err)
	}
	checkCompat(t, dir, m, func(e *Engine) error {
		if err := e.UnlockDatabase(m.Password); err != nil {
			return err
		}
		return e.RestoreBackup(bk.Path, m.Password, nil)
	})
}

func loadManifest(t *testing.T, version string) compatManifest {
	t.Helper()
	data, err := os.ReadFile(fixtureFile(t, version, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m compatManifest
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	return m
}
