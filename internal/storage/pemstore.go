package storage

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// pemBundle is the serialized form of a persisted certificate and its key.
type pemBundle struct {
	CertPEM []byte `json:"certPem"`
	KeyPEM  []byte `json:"keyPem"`
}

// PEMStore persists one certificate and its private key, so that what the
// application generated is still there after a restart.
//
// Two of them exist, one per thing that must survive: the CA, so device
// certificates can still be signed, and the server's own TLS identity, so the
// certificate a client was told to trust is the one it meets after a reboot.
// Losing the second was worse than inconvenient — the listener quietly fell
// back to a fresh self-signed certificate, and every client that trusted the CA
// or had pinned the fingerprint refused the connection.
//
// When an encryption password is set, the bundle is stored with the same
// AES-256-GCM/Argon2id scheme used for the log database. Without a
// password the bundle is stored as plaintext PEM at file mode 0600; the
// private key then rests unencrypted on disk, which the caller is
// expected to surface to the user.
type PEMStore struct {
	dir       string
	plainName string
	encName   string
}

// NewCAStore creates the store for the generated CA, in the given directory
// (typically the same directory used by ConfigStore). An empty dir disables
// persistence.
func NewCAStore(dir string) *PEMStore {
	return &PEMStore{dir: dir, plainName: "ca.json", encName: "ca.json.enc"}
}

// NewServerCertStore creates the store for the server's generated TLS
// identity: the certificate the assistant produced, self-signed or signed by
// the CA. Certificates the operator supplies as files are not copied here; the
// files remain theirs.
func NewServerCertStore(dir string) *PEMStore {
	return &PEMStore{dir: dir, plainName: "server-cert.json", encName: "server-cert.json.enc"}
}

func (s *PEMStore) plainPath() string { return filepath.Join(s.dir, s.plainName) }
func (s *PEMStore) encPath() string   { return filepath.Join(s.dir, s.encName) }

// Exists reports whether a persisted bundle (encrypted or plaintext) is present.
func (s *PEMStore) Exists() bool {
	if s.dir == "" {
		return false
	}
	if _, err := os.Stat(s.encPath()); err == nil {
		return true
	}
	_, err := os.Stat(s.plainPath())
	return err == nil
}

// Save persists the material. If password is non-empty the bundle is
// encrypted; otherwise it is written as plaintext PEM at 0600. Any
// counterpart file from the other mode is removed to avoid stale copies.
func (s *PEMStore) Save(certPEM, keyPEM []byte, password string) error {
	if s.dir == "" {
		return fmt.Errorf("no config directory available to persist %s", s.plainName)
	}
	if err := os.MkdirAll(s.dir, 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	data, err := json.Marshal(pemBundle{CertPEM: certPEM, KeyPEM: keyPEM})
	if err != nil {
		return fmt.Errorf("marshal %s: %w", s.plainName, err)
	}

	if password != "" {
		enc, err := EncryptBytes(data, password)
		if err != nil {
			return fmt.Errorf("encrypt %s: %w", s.plainName, err)
		}
		if err := writeFileSync(s.encPath(), enc, 0600); err != nil {
			return fmt.Errorf("write %s: %w", s.encName, err)
		}
		_ = os.Remove(s.plainPath())
		return nil
	}

	if err := writeFileSync(s.plainPath(), data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", s.plainName, err)
	}
	_ = os.Remove(s.encPath())
	return nil
}

// Load reads the persisted material. If the stored bundle is encrypted,
// password must be the correct password. Returns (nil, nil, nil) when nothing
// is persisted.
func (s *PEMStore) Load(password string) (certPEM, keyPEM []byte, err error) {
	if s.dir == "" {
		return nil, nil, nil
	}

	var raw []byte
	if enc, rerr := os.ReadFile(s.encPath()); rerr == nil {
		if password == "" {
			return nil, nil, fmt.Errorf("%s is encrypted but no password was provided", s.plainName)
		}
		dec, derr := DecryptBytes(enc, password)
		if derr != nil {
			return nil, nil, derr
		}
		raw = dec
	} else if plain, rerr := os.ReadFile(s.plainPath()); rerr == nil {
		raw = plain
	} else {
		return nil, nil, nil // nothing persisted
	}

	var bundle pemBundle
	if err := json.Unmarshal(raw, &bundle); err != nil {
		return nil, nil, fmt.Errorf("parse %s: %w", s.plainName, err)
	}
	return bundle.CertPEM, bundle.KeyPEM, nil
}

// IsEncrypted reports whether the persisted bundle is the encrypted variant.
func (s *PEMStore) IsEncrypted() bool {
	if s.dir == "" {
		return false
	}
	_, err := os.Stat(s.encPath())
	return err == nil
}
