package engine

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/notify"
	"SyslogStudio/internal/storage"
)

type xorSealer struct{}

func (xorSealer) Seal(p []byte) ([]byte, error)   { return xorBytes(p), nil }
func (xorSealer) Unseal(p []byte) ([]byte, error) { return xorBytes(p), nil }

func xorBytes(p []byte) []byte {
	out := make([]byte, len(p))
	for i, b := range p {
		out[i] = b ^ 0x5a
	}
	return out
}

func webhookSink() notify.SinkConfig {
	return notify.SinkConfig{
		ID: "sink-1", Name: "on-call", Kind: notify.SinkWebhook, Enabled: true,
		Webhook: notify.WebhookSinkConfig{URL: "https://hooks.example.invalid/alert", Method: "POST"},
	}
}

// What the installer does: the desktop engine describes itself, a fresh engine
// in another directory adopts the description, sealed, with encryption off.
func TestBundle_RoundTripIntoASealedEngine(t *testing.T) {
	desk := New(storage.NewConfigStoreAt(t.TempDir()))
	if err := desk.EnableEncryption("correct horse battery"); err != nil {
		t.Fatal(err)
	}
	server := models.DefaultServerConfig()
	server.TLSEnabled, server.UseSelfSigned, server.TLSPort = true, true, 6514
	desk.SaveServerConfig(server)
	desk.configStore.SaveAlertRules([]models.AlertRule{{ID: "r1", Name: "auth failures", Enabled: true, Pattern: "Failed password"}})
	if _, err := desk.GenerateCertificate(models.CertOptions{Algorithm: "ECDSA-P256"}); err != nil {
		t.Fatal(err)
	}
	sink := webhookSink()
	sink.Secret = "bearer-token-value"
	if err := desk.SaveNotifySink(sink); err != nil {
		t.Fatal(err)
	}

	b, err := desk.ExportBundle()
	if err != nil {
		t.Fatal(err)
	}
	if b.Storage.EncryptionEnabled || b.Storage.Path != "" {
		t.Fatal("the bundle must leave the database to the receiving engine, unencrypted")
	}

	svcDir := t.TempDir()
	svc := New(storage.NewConfigStoreAt(svcDir))
	svc.SetSealer(xorSealer{})
	if err := svc.ImportBundle(b); err != nil {
		t.Fatal(err)
	}

	if got := svc.configStore.Load(); !got.TLSEnabled || got.TLSPort != 6514 {
		t.Errorf("listeners not adopted: %+v", got)
	}
	if rules := svc.configStore.LoadAlertRules(); len(rules) != 1 || rules[0].Name != "auth failures" {
		t.Errorf("alert rules not adopted: %+v", rules)
	}
	if svc.configStore.LoadStorage().EncryptionEnabled {
		t.Error("the receiving engine was left with encryption on and no password")
	}
	dest, _ := notify.Destination(webhookSink())
	if got := svc.secretStore.Get("sink-1", dest); got != "bearer-token-value" {
		t.Errorf("credential not adopted: %q", got)
	}
	for _, s := range svc.configStore.LoadSinks() {
		if s.Secret != "" {
			t.Fatal("a credential reached config.json")
		}
	}
	cfg, _ := os.ReadFile(filepath.Join(svcDir, "config.json"))
	if bytes.Contains(cfg, []byte("bearer-token-value")) {
		t.Fatal("a credential reached config.json")
	}

	// The identity is the desktop's, and sealed at rest.
	want, _, _ := desk.tlsManager.GetServerMaterial()
	again := New(storage.NewConfigStoreAt(svcDir))
	again.SetSealer(xorSealer{})
	if err := again.loadPersistedServerCert(); err != nil {
		t.Fatal(err)
	}
	got, _, _ := again.tlsManager.GetServerMaterial()
	if !bytes.Equal(got, want) {
		t.Fatal("the service would present a different certificate")
	}
	raw, _ := os.ReadFile(filepath.Join(svcDir, "server-cert.json"))
	if bytes.Contains(raw, []byte("PRIVATE KEY")) {
		t.Fatal("the TLS key is on disk in the clear")
	}
}

// Certificates given as files become a stored identity in the bundle: a
// service cannot be assumed to read a file in someone's profile.
func TestBundle_FileCertificatesTravelAsContent(t *testing.T) {
	gen := New(storage.NewConfigStoreAt(t.TempDir()))
	if _, err := gen.GenerateCertificate(models.CertOptions{Algorithm: "ECDSA-P256"}); err != nil {
		t.Fatal(err)
	}
	certPEM, keyPEM, _ := gen.tlsManager.GetServerMaterial()
	dir := t.TempDir()
	certPath, keyPath, caPath := filepath.Join(dir, "c.pem"), filepath.Join(dir, "k.pem"), filepath.Join(dir, "ca.pem")
	os.WriteFile(certPath, certPEM, 0644)
	os.WriteFile(keyPath, keyPEM, 0600)
	os.WriteFile(caPath, certPEM, 0644)

	desk := New(storage.NewConfigStoreAt(t.TempDir()))
	server := models.DefaultServerConfig()
	server.TLSEnabled, server.UseSelfSigned = true, false
	server.CertFile, server.KeyFile = certPath, keyPath
	server.MutualTLS, server.CAFile = true, caPath
	desk.SaveServerConfig(server)

	b, err := desk.ExportBundle()
	if err != nil {
		t.Fatal(err)
	}
	if !b.Server.UseSelfSigned || b.Server.CertFile != "" || b.Server.KeyFile != "" {
		t.Errorf("file paths travelled instead of the identity: %+v", b.Server)
	}
	if !bytes.Equal(b.TLSKeyPEM, keyPEM) || len(b.ClientCAPEM) == 0 {
		t.Fatal("the certificate files' content is missing from the bundle")
	}

	svcDir := t.TempDir()
	svc := New(storage.NewConfigStoreAt(svcDir))
	if err := svc.ImportBundle(b); err != nil {
		t.Fatal(err)
	}
	got := svc.configStore.Load()
	if !strings.HasPrefix(got.CAFile, svcDir) {
		t.Errorf("the client CA should be read from the service's own directory, got %q", got.CAFile)
	}
}

func TestBundle_RefusesALockedEngine(t *testing.T) {
	dir := t.TempDir()
	cs := storage.NewConfigStoreAt(dir)
	e := New(cs)
	e.logStore = lockedLogStore(t, dir)
	if _, err := e.ExportBundle(); err == nil || !strings.Contains(err.Error(), "unlock") {
		t.Fatalf("exporting a locked engine should ask for an unlock, got %v", err)
	}
}

// lockedLogStore opens a store over an encrypted database file, which leaves
// it locked until a password is given.
func lockedLogStore(t *testing.T, dir string) *storage.LogStore {
	t.Helper()
	path := filepath.Join(dir, "logs.db")
	if err := os.WriteFile(path+".enc", []byte("not really encrypted"), 0600); err != nil {
		t.Fatal(err)
	}
	ls, err := storage.NewLogStore(models.StorageConfig{Enabled: true, Path: path, EncryptionEnabled: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !ls.IsLocked() {
		t.Fatal("the store should be locked")
	}
	return ls
}

func TestBundle_RejectsAnotherVersion(t *testing.T) {
	e := New(storage.NewConfigStoreAt(t.TempDir()))
	if err := e.ImportBundle(Bundle{Version: BundleVersion + 1}); err == nil {
		t.Fatal("a bundle from a newer version was accepted")
	}
}
