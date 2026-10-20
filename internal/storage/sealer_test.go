package storage

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// xorSealer stands in for DPAPI: reversible, and visibly not plaintext.
type xorSealer struct{}

func (xorSealer) Seal(p []byte) ([]byte, error)   { return xor(p), nil }
func (xorSealer) Unseal(p []byte) ([]byte, error) { return xor(p), nil }

func xor(p []byte) []byte {
	out := make([]byte, len(p))
	for i, b := range p {
		out[i] = b ^ 0x5a
	}
	return out
}

func TestSecretStore_SealsWhatWouldBePlaintext(t *testing.T) {
	dir := t.TempDir()
	s := NewSecretStore(dir)
	s.SetSealer(xorSealer{})
	if err := s.Set("sink-1", "https://hooks.example.invalid", "bearer-token-value"); err != nil {
		t.Fatal(err)
	}

	raw, err := os.ReadFile(filepath.Join(dir, "sinksecrets.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("bearer-token-value")) {
		t.Fatal("the credential is on disk in the clear")
	}

	again := NewSecretStore(dir)
	again.SetSealer(xorSealer{})
	if got := again.Get("sink-1", "https://hooks.example.invalid"); got != "bearer-token-value" {
		t.Fatalf("read back %q", got)
	}

	// Without the sealer the file is refused, not misread.
	plain := NewSecretStore(dir)
	if got := plain.Get("sink-1", "https://hooks.example.invalid"); got != "" {
		t.Fatalf("a store without the sealer read %q", got)
	}
}

// A plaintext file from before sealing was turned on is still read, and sealed
// the next time the store is written.
func TestSecretStore_SealsAnExistingPlaintextFileOnNextSave(t *testing.T) {
	dir := t.TempDir()
	plain := NewSecretStore(dir)
	if err := plain.Set("sink-1", "smtp://mail.example.invalid", "old-password"); err != nil {
		t.Fatal(err)
	}

	sealed := NewSecretStore(dir)
	sealed.SetSealer(xorSealer{})
	if got := sealed.Get("sink-1", "smtp://mail.example.invalid"); got != "old-password" {
		t.Fatalf("existing plaintext credential not read: %q", got)
	}
	if err := sealed.Set("sink-2", "smtp://mail.example.invalid", "new-password"); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "sinksecrets.json"))
	if bytes.Contains(raw, []byte("old-password")) {
		t.Fatal("the old credential stayed in the clear after a sealed save")
	}
}

func TestPEMStore_Sealed(t *testing.T) {
	dir := t.TempDir()
	s := NewServerCertStore(dir)
	s.SetSealer(xorSealer{})
	if err := s.Save([]byte("CERT"), []byte("PRIVATE-KEY-BYTES"), ""); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "server-cert.json"))
	if bytes.Contains(raw, []byte("PRIVATE-KEY-BYTES")) {
		t.Fatal("the private key is on disk in the clear")
	}
	cert, key, err := s.Load("")
	if err != nil || string(cert) != "CERT" || string(key) != "PRIVATE-KEY-BYTES" {
		t.Fatalf("roundtrip: %q %q %v", cert, key, err)
	}

	if _, _, err := NewServerCertStore(dir).Load(""); !errors.Is(err, ErrSealed) {
		t.Fatalf("an unsealing-less store should report ErrSealed, got %v", err)
	}
}
