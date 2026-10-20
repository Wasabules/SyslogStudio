package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
)

// The server's TLS identity used to live in memory only. These tests follow
// it through what an operator actually does: generate it with encryption on,
// restart, start TLS before and after unlocking.

const identityPassword = "correct horse battery"

func ecdsaOpts() models.CertOptions {
	return models.CertOptions{Algorithm: "ECDSA-P256", DNSNames: []string{"localhost"}}
}

func TestServerIdentity_PersistedEncryptedAndRestoredAfterUnlock(t *testing.T) {
	dir := t.TempDir()
	a := newAppIn(storage.NewConfigStoreAt(dir))
	if err := a.EnableEncryption(identityPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GenerateCA(ecdsaOpts()); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GenerateServerCert(ecdsaOpts()); err != nil {
		t.Fatal(err)
	}
	if !a.serverCertStore.IsEncrypted() {
		t.Fatal("the server identity was not persisted encrypted")
	}
	wantCert, _, _ := a.tlsManager.GetServerMaterial()

	// Restart, still locked: the identity is on disk but not readable.
	b := newAppIn(storage.NewConfigStoreAt(dir))
	if b.tlsManager.HasServerCert() {
		t.Fatal("an encrypted identity was loaded without the password")
	}
	err := b.StartServer(models.ServerConfig{TLSEnabled: true, TLSPort: 6514, UseSelfSigned: true})
	if err == nil || !strings.Contains(err.Error(), "unlock") {
		t.Fatalf("starting TLS with the saved identity still locked should ask for an unlock, got %v", err)
	}

	// Unlocked: the very same certificate comes back.
	b.encryptionPassword = identityPassword
	if err := b.loadPersistedServerCert(); err != nil {
		t.Fatal(err)
	}
	gotCert, _, ok := b.tlsManager.GetServerMaterial()
	if !ok || !bytes.Equal(gotCert, wantCert) {
		t.Fatal("the restored identity is not the one that was generated")
	}
}

// Generating while locked must not destroy the encrypted copy: writing without
// the password would land in plaintext and remove the .enc file.
func TestServerIdentity_NotOverwrittenWhileLocked(t *testing.T) {
	dir := t.TempDir()
	a := newAppIn(storage.NewConfigStoreAt(dir))
	if err := a.EnableEncryption(identityPassword); err != nil {
		t.Fatal(err)
	}
	if _, err := a.GenerateCertificate(ecdsaOpts()); err != nil {
		t.Fatal(err)
	}
	encPath := filepath.Join(dir, "server-cert.json.enc")
	before, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("no encrypted identity on disk: %v", err)
	}

	locked := newAppIn(storage.NewConfigStoreAt(dir))
	if _, err := locked.GenerateCertificate(ecdsaOpts()); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatalf("the encrypted identity was removed: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Error("the encrypted identity was rewritten without the password")
	}
	if _, err := os.Stat(filepath.Join(dir, "server-cert.json")); !os.IsNotExist(err) {
		t.Error("a plaintext copy of the key was written while locked")
	}
}

// Turning encryption off rewrites the identity in plaintext, and on again
// encrypts it — the same as the CA, so neither lingers in the other form.
func TestServerIdentity_FollowsEncryptionToggles(t *testing.T) {
	dir := t.TempDir()
	a := newAppIn(storage.NewConfigStoreAt(dir))
	if _, err := a.GenerateCertificate(ecdsaOpts()); err != nil {
		t.Fatal(err)
	}
	if !a.serverCertStore.Exists() || a.serverCertStore.IsEncrypted() {
		t.Fatal("without encryption the identity should be persisted in plaintext")
	}
	if err := a.EnableEncryption(identityPassword); err != nil {
		t.Fatal(err)
	}
	if !a.serverCertStore.IsEncrypted() {
		t.Fatal("enabling encryption did not encrypt the identity")
	}
	if err := a.DisableEncryption(identityPassword); err != nil {
		t.Fatal(err)
	}
	if a.serverCertStore.IsEncrypted() {
		t.Fatal("disabling encryption left the identity encrypted")
	}
}
