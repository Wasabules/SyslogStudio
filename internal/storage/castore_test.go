package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestEncryptDecryptBytes_Roundtrip(t *testing.T) {
	plaintext := []byte("-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----")
	enc, err := EncryptBytes(plaintext, "correct horse battery staple")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if bytes.Equal(enc, plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	dec, err := DecryptBytes(enc, "correct horse battery staple")
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if !bytes.Equal(dec, plaintext) {
		t.Fatal("roundtrip mismatch")
	}
}

func TestDecryptBytes_WrongPassword(t *testing.T) {
	enc, err := EncryptBytes([]byte("secret"), "right")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptBytes(enc, "wrong"); err != ErrWrongPassword {
		t.Errorf("expected ErrWrongPassword, got %v", err)
	}
}

func TestDecryptBytes_Tampered(t *testing.T) {
	enc, err := EncryptBytes([]byte("secret"), "pw")
	if err != nil {
		t.Fatal(err)
	}
	enc[len(enc)-1] ^= 0xFF // flip a ciphertext bit
	if _, err := DecryptBytes(enc, "pw"); err != ErrWrongPassword {
		t.Errorf("expected ErrWrongPassword on tamper, got %v", err)
	}
}

func TestDecryptBytes_ShortInput(t *testing.T) {
	if _, err := DecryptBytes([]byte{0x01, 0x02}, "pw"); err != ErrInvalidFile {
		t.Errorf("expected ErrInvalidFile, got %v", err)
	}
}

func TestCAStore_PlaintextRoundtrip(t *testing.T) {
	dir := t.TempDir()
	cs := NewCAStore(dir)

	cert := []byte("CERT-PEM")
	key := []byte("KEY-PEM")
	if err := cs.Save(cert, key, ""); err != nil {
		t.Fatalf("save: %v", err)
	}
	if !cs.Exists() {
		t.Fatal("Exists should be true after save")
	}
	if cs.IsEncrypted() {
		t.Fatal("plaintext save must not be flagged encrypted")
	}

	// Key file must be 0600.
	info, err := os.Stat(filepath.Join(dir, caStoreFileName))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("CA bundle perm = %o, want 0600", perm)
	}

	gotCert, gotKey, err := cs.Load("")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !bytes.Equal(gotCert, cert) || !bytes.Equal(gotKey, key) {
		t.Fatal("plaintext roundtrip mismatch")
	}
}

func TestCAStore_EncryptedRoundtrip(t *testing.T) {
	dir := t.TempDir()
	cs := NewCAStore(dir)

	cert := []byte("CERT-PEM")
	key := []byte("KEY-PEM")
	if err := cs.Save(cert, key, "pw"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if !cs.IsEncrypted() {
		t.Fatal("encrypted save should be flagged encrypted")
	}

	// Wrong password must fail.
	if _, _, err := cs.Load("nope"); err != ErrWrongPassword {
		t.Errorf("expected ErrWrongPassword, got %v", err)
	}

	// No password against an encrypted store must fail clearly.
	if _, _, err := cs.Load(""); err == nil {
		t.Error("loading encrypted CA without a password should fail")
	}

	gotCert, gotKey, err := cs.Load("pw")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if !bytes.Equal(gotCert, cert) || !bytes.Equal(gotKey, key) {
		t.Fatal("encrypted roundtrip mismatch")
	}
}

func TestCAStore_SwitchModesRemovesStale(t *testing.T) {
	dir := t.TempDir()
	cs := NewCAStore(dir)

	if err := cs.Save([]byte("c"), []byte("k"), ""); err != nil {
		t.Fatal(err)
	}
	// Switch to encrypted; plaintext file should be removed.
	if err := cs.Save([]byte("c"), []byte("k"), "pw"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, caStoreFileName)); !os.IsNotExist(err) {
		t.Error("plaintext CA file should be removed after switching to encrypted")
	}
	if !cs.IsEncrypted() {
		t.Error("store should be encrypted after switch")
	}
}

func TestCAStore_EmptyWhenNothingSaved(t *testing.T) {
	cs := NewCAStore(t.TempDir())
	if cs.Exists() {
		t.Fatal("Exists should be false for an empty store")
	}
	cert, key, err := cs.Load("")
	if err != nil {
		t.Fatalf("load on empty store should not error: %v", err)
	}
	if cert != nil || key != nil {
		t.Fatal("empty store should return nil material")
	}
}
