package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

const (
	secretStoreFileName    = "sinksecrets.json"     // plaintext, 0600
	secretStoreEncFileName = "sinksecrets.json.enc" // AES-256-GCM
)

// storedSecret is one credential plus the destination it was stored against.
//
// The destination is kept alongside the value because a credential may only be
// used with the place it was given for. Without it, naming an existing sink's
// id while pointing the URL at your own server has the app hand you the bearer
// token or the SMTP password.
type storedSecret struct {
	Value       string `json:"value"`
	Destination string `json:"destination"`
}

// SecretStore persists sink credentials, encrypted with the same AES-256-GCM
// and Argon2id used for the log database and the CA.
//
// When at-rest encryption is off, the file is plaintext at 0600 — the same
// trade the CA store makes, and the caller surfaces it the same way. Making
// credentials the one thing that refuses to work without encryption would mean
// a webhook silently stopping when someone turns encryption off.
type SecretStore struct {
	dir string

	mu       sync.Mutex
	password string
	cache    map[string]storedSecret
	loaded   bool
}

// NewSecretStore creates a store in the given directory. An empty dir disables
// persistence, which is how the app behaves when it cannot find a config
// directory at all.
func NewSecretStore(dir string) *SecretStore {
	return &SecretStore{dir: dir, cache: make(map[string]storedSecret)}
}

func (s *SecretStore) plainPath() string { return filepath.Join(s.dir, secretStoreFileName) }
func (s *SecretStore) encPath() string   { return filepath.Join(s.dir, secretStoreEncFileName) }

// SetPassword installs the session password. Called after the database is
// unlocked, or when encryption is enabled or disabled.
func (s *SecretStore) SetPassword(password string) {
	s.mu.Lock()
	changed := s.password != password
	s.password = password
	if changed {
		// The cache was decrypted with the previous password; drop it so the
		// next read goes back to disk under the new one.
		s.loaded = false
		s.cache = make(map[string]storedSecret)
	}
	s.mu.Unlock()
}

// IsEncrypted reports whether the stored file is the encrypted variant, so the
// UI can warn when credentials rest in plaintext.
func (s *SecretStore) IsEncrypted() bool {
	if s.dir == "" {
		return false
	}
	_, err := os.Stat(s.encPath())
	return err == nil
}

// HasAny reports whether any credential is on file.
func (s *SecretStore) HasAny() bool {
	if s.dir == "" {
		return false
	}
	if _, err := os.Stat(s.encPath()); err == nil {
		return true
	}
	_, err := os.Stat(s.plainPath())
	return err == nil
}

// load reads the store. Must be called with the lock held.
func (s *SecretStore) load() error {
	if s.loaded || s.dir == "" {
		return nil
	}

	var raw []byte
	if enc, err := os.ReadFile(s.encPath()); err == nil {
		if s.password == "" {
			return fmt.Errorf("credentials are encrypted; unlock the database first")
		}
		dec, derr := DecryptBytes(enc, s.password)
		if derr != nil {
			return derr
		}
		raw = dec
	} else if plain, err := os.ReadFile(s.plainPath()); err == nil {
		raw = plain
	} else {
		s.loaded = true
		return nil // nothing stored yet
	}

	var m map[string]storedSecret
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("parse credential store: %w", err)
	}
	s.cache = m
	if s.cache == nil {
		s.cache = make(map[string]storedSecret)
	}
	s.loaded = true
	return nil
}

// save writes the store. Must be called with the lock held.
func (s *SecretStore) save() error {
	if s.dir == "" {
		return fmt.Errorf("no config directory available to store credentials")
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.Marshal(s.cache)
	if err != nil {
		return err
	}

	if s.password != "" {
		enc, err := EncryptBytes(data, s.password)
		if err != nil {
			return fmt.Errorf("encrypt credentials: %w", err)
		}
		if err := os.WriteFile(s.encPath(), enc, 0600); err != nil {
			return err
		}
		// Remove the counterpart so a stale plaintext copy cannot outlive the
		// switch to encryption.
		_ = os.Remove(s.plainPath())
		return nil
	}

	if err := os.WriteFile(s.plainPath(), data, 0600); err != nil {
		return err
	}
	_ = os.Remove(s.encPath())
	return nil
}

// Set stores a credential for a sink, bound to a destination.
func (s *SecretStore) Set(sinkID, destination, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	s.cache[sinkID] = storedSecret{Value: value, Destination: destination}
	return s.save()
}

// Get returns the credential for a sink, but ONLY if the caller's destination
// matches the one it was stored against.
//
// A mismatch returns empty rather than an error: the delivery then fails at the
// far end with an authentication error, which is the correct outcome and says
// nothing about whether a credential exists for some other destination.
func (s *SecretStore) Get(sinkID, destination string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return ""
	}
	got, ok := s.cache[sinkID]
	if !ok || got.Destination != destination {
		return ""
	}
	return got.Value
}

// Has reports whether a credential is on file for a sink, without returning it.
// This is what lets the UI show "configured" while the value stays write-only.
func (s *SecretStore) Has(sinkID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return false
	}
	_, ok := s.cache[sinkID]
	return ok
}

// Delete removes a sink's credential.
func (s *SecretStore) Delete(sinkID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	if _, ok := s.cache[sinkID]; !ok {
		return nil
	}
	delete(s.cache, sinkID)
	return s.save()
}

// Prune removes credentials whose sink no longer exists, so deleting a
// destination does not leave its password on disk forever.
func (s *SecretStore) Prune(keep map[string]bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	changed := false
	for id := range s.cache {
		if !keep[id] {
			delete(s.cache, id)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.save()
}

// Rewrite re-persists the store under the current password. Called when
// encryption is turned on or off, or the password changes, so credentials do
// not stay behind in the previous form.
func (s *SecretStore) Rewrite() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.load(); err != nil {
		return err
	}
	if len(s.cache) == 0 {
		return nil
	}
	return s.save()
}
