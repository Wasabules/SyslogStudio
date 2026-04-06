package storage

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDeriveKey_Deterministic(t *testing.T) {
	salt := []byte("1234567890123456")
	k1 := DeriveKey("mypassword", salt)
	k2 := DeriveKey("mypassword", salt)
	if !bytes.Equal(k1, k2) {
		t.Error("same password+salt should produce same key")
	}
	if len(k1) != keyLen {
		t.Errorf("expected key length %d, got %d", keyLen, len(k1))
	}
}

func TestDeriveKey_DifferentPasswords(t *testing.T) {
	salt := []byte("1234567890123456")
	k1 := DeriveKey("password1", salt)
	k2 := DeriveKey("password2", salt)
	if bytes.Equal(k1, k2) {
		t.Error("different passwords should produce different keys")
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.db")
	encPath := filepath.Join(dir, "test.db.enc")
	decPath := filepath.Join(dir, "test_dec.db")

	original := []byte("Hello, this is a test database content with some syslog data!")
	if err := os.WriteFile(srcPath, original, 0600); err != nil {
		t.Fatal(err)
	}

	if err := EncryptFile(srcPath, encPath, "testpassword"); err != nil {
		t.Fatalf("encrypt failed: %v", err)
	}

	// Encrypted file should exist and differ from original
	encData, err := os.ReadFile(encPath)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(encData, original) {
		t.Error("encrypted data should differ from original")
	}
	if len(encData) < headerLen {
		t.Error("encrypted file too short")
	}
	if encData[0] != encFileVersion {
		t.Errorf("expected version %d, got %d", encFileVersion, encData[0])
	}

	// Decrypt
	if err := DecryptFile(encPath, decPath, "testpassword"); err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}

	decData, err := os.ReadFile(decPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(decData, original) {
		t.Error("decrypted data should match original")
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.db")
	encPath := filepath.Join(dir, "test.db.enc")
	decPath := filepath.Join(dir, "test_dec.db")

	if err := os.WriteFile(srcPath, []byte("secret data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(srcPath, encPath, "correctpassword"); err != nil {
		t.Fatal(err)
	}

	err := DecryptFile(encPath, decPath, "wrongpassword")
	if err != ErrWrongPassword {
		t.Errorf("expected ErrWrongPassword, got %v", err)
	}

	// Decrypted file should not exist
	if _, err := os.Stat(decPath); err == nil {
		t.Error("decrypted file should not exist after wrong password")
	}
}

func TestDecryptCorruptedFile(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "test.db")
	encPath := filepath.Join(dir, "test.db.enc")
	decPath := filepath.Join(dir, "test_dec.db")

	if err := os.WriteFile(srcPath, []byte("important data"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := EncryptFile(srcPath, encPath, "password"); err != nil {
		t.Fatal(err)
	}

	// Corrupt a byte in the ciphertext area
	data, _ := os.ReadFile(encPath)
	data[headerLen+5] ^= 0xFF
	os.WriteFile(encPath, data, 0600)

	err := DecryptFile(encPath, decPath, "password")
	if err != ErrWrongPassword {
		t.Errorf("expected ErrWrongPassword for corrupted file, got %v", err)
	}
}

func TestDecryptInvalidFile(t *testing.T) {
	dir := t.TempDir()
	encPath := filepath.Join(dir, "bad.enc")
	decPath := filepath.Join(dir, "out.db")

	// Too short
	os.WriteFile(encPath, []byte("short"), 0600)
	err := DecryptFile(encPath, decPath, "password")
	if err != ErrInvalidFile {
		t.Errorf("expected ErrInvalidFile for short file, got %v", err)
	}
}

func TestEncryptedFileExists(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "logs.db")

	if EncryptedFileExists(dbPath) {
		t.Error("should return false when .enc doesn't exist")
	}

	os.WriteFile(dbPath+".enc", []byte("encrypted"), 0600)
	if !EncryptedFileExists(dbPath) {
		t.Error("should return true when .enc exists")
	}
}

func TestEncryptEmptyFile(t *testing.T) {
	dir := t.TempDir()
	srcPath := filepath.Join(dir, "empty.db")
	encPath := filepath.Join(dir, "empty.db.enc")
	decPath := filepath.Join(dir, "empty_dec.db")

	os.WriteFile(srcPath, []byte{}, 0600)
	if err := EncryptFile(srcPath, encPath, "password"); err != nil {
		t.Fatal(err)
	}
	if err := DecryptFile(encPath, decPath, "password"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(decPath)
	if len(data) != 0 {
		t.Error("decrypted empty file should be empty")
	}
}
