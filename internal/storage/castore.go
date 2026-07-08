package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	caStoreFileName    = "ca.json"     // plaintext PEM bundle (key at 0600)
	caStoreEncFileName = "ca.json.enc" // AES-256-GCM encrypted bundle
)

// caBundle is the serialized form of a persisted CA.
type caBundle struct {
	CertPEM []byte `json:"certPem"`
	KeyPEM  []byte `json:"keyPem"`
}

// CAStore persists a generated CA certificate and its private key so that
// device certificates can still be signed after an application restart.
//
// When an encryption password is set, the bundle is stored with the same
// AES-256-GCM/Argon2id scheme used for the log database. Without a
// password the bundle is stored as plaintext PEM at file mode 0600; the
// private key then rests unencrypted on disk, which the caller is
// expected to surface to the user.
type CAStore struct {
	dir string
}

// NewCAStore creates a CAStore in the given directory (typically the same
// directory used by ConfigStore). An empty dir disables persistence.
func NewCAStore(dir string) *CAStore {
	return &CAStore{dir: dir}
}

func (cs *CAStore) plainPath() string { return filepath.Join(cs.dir, caStoreFileName) }
func (cs *CAStore) encPath() string   { return filepath.Join(cs.dir, caStoreEncFileName) }

// Exists reports whether a persisted CA (encrypted or plaintext) is present.
func (cs *CAStore) Exists() bool {
	if cs.dir == "" {
		return false
	}
	if _, err := os.Stat(cs.encPath()); err == nil {
		return true
	}
	_, err := os.Stat(cs.plainPath())
	return err == nil
}

// Save persists the CA material. If password is non-empty the bundle is
// encrypted; otherwise it is written as plaintext PEM at 0600. Any
// counterpart file from the other mode is removed to avoid stale copies.
func (cs *CAStore) Save(certPEM, keyPEM []byte, password string) error {
	if cs.dir == "" {
		return fmt.Errorf("no config directory available to persist CA")
	}
	if err := os.MkdirAll(cs.dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.Marshal(caBundle{CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		return fmt.Errorf("marshal CA bundle: %w", err)
	}

	if password != "" {
		enc, err := EncryptBytes(data, password)
		if err != nil {
			return fmt.Errorf("encrypt CA bundle: %w", err)
		}
		if err := os.WriteFile(cs.encPath(), enc, 0600); err != nil {
			return fmt.Errorf("write encrypted CA: %w", err)
		}
		_ = os.Remove(cs.plainPath())
		return nil
	}

	if err := os.WriteFile(cs.plainPath(), data, 0600); err != nil {
		return fmt.Errorf("write CA bundle: %w", err)
	}
	_ = os.Remove(cs.encPath())
	return nil
}

// Load reads the persisted CA material. If the stored bundle is encrypted,
// password must be the correct password. Returns (nil, nil, nil) when no
// CA is persisted.
func (cs *CAStore) Load(password string) (certPEM, keyPEM []byte, err error) {
	if cs.dir == "" {
		return nil, nil, nil
	}

	var raw []byte
	if enc, rerr := os.ReadFile(cs.encPath()); rerr == nil {
		if password == "" {
			return nil, nil, fmt.Errorf("CA is encrypted but no password was provided")
		}
		dec, derr := DecryptBytes(enc, password)
		if derr != nil {
			return nil, nil, derr
		}
		raw = dec
	} else if plain, rerr := os.ReadFile(cs.plainPath()); rerr == nil {
		raw = plain
	} else {
		return nil, nil, nil // nothing persisted
	}

	var bundle caBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, nil, fmt.Errorf("parse CA bundle: %w", err)
	}
	return bundle.CertPEM, bundle.KeyPEM, nil
}

// IsEncrypted reports whether the persisted CA bundle is the encrypted variant.
func (cs *CAStore) IsEncrypted() bool {
	if cs.dir == "" {
		return false
	}
	_, err := os.Stat(cs.encPath())
	return err == nil
}
