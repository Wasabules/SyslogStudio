package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"SyslogStudio/internal/vault"
)

// The keyring holds the locks on an installation's master secret: one for the
// password and, once there is one, one for the recovery key. It is what the
// password opens; the master secret it yields is what the database, the CA,
// the credentials and the inbox key are encrypted with (see internal/vault).
//
// An installation encrypted before the keyring existed has no keyring file:
// its password is its master secret. The first unlock writes one — still with
// the password as master, so nothing else changes — and the next change of
// password replaces it with a random one.

const keyringFileName = "keyring.json"

// Keyring is keyring.json.
type Keyring struct {
	Version int          `json:"v"`
	Slots   []vault.Slot `json:"slots,omitempty"`
	// Recovery is the recovery key, public half only. Kept when encryption is
	// off too: backups are then locked to it alone.
	Recovery *RecoveryKey `json:"recovery,omitempty"`
	// Previous is the master secret being replaced, sealed by the new one,
	// while what it encrypted is being written again: a file the rewrite
	// missed — an interruption, a full disk — is still read, and written under
	// the new one then. Gone once nothing needs it.
	Previous []byte `json:"previous,omitempty"`
}

// RecoveryKey is the public half of a recovery key and what names it.
type RecoveryKey struct {
	ID      string `json:"id"`
	Created string `json:"created"`
	Public  []byte `json:"public"`
}

// ErrNoKeyring is an installation without a keyring file.
var ErrNoKeyring = errors.New("no keyring")

func keyringPath(dir string) string { return filepath.Join(dir, keyringFileName) }

// LoadKeyring reads the keyring of the data directory dir.
func LoadKeyring(dir string) (Keyring, error) {
	data, err := os.ReadFile(keyringPath(dir))
	if errors.Is(err, os.ErrNotExist) {
		return Keyring{}, ErrNoKeyring
	}
	if err != nil {
		return Keyring{}, err
	}
	var k Keyring
	if err := json.Unmarshal(data, &k); err != nil {
		return Keyring{}, fmt.Errorf("the keyring is damaged: %w", err)
	}
	return k, nil
}

// SaveKeyring writes the keyring, whole or not at all.
func SaveKeyring(dir string, k Keyring) error {
	k.Version = 1
	data, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	path := keyringPath(dir)
	tmp := path + ".part"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// PasswordSlots are the keyring's password locks.
func (k Keyring) PasswordSlots() []vault.Slot { return k.slotsOf(vault.KindPassword) }

// KeySlots are its recovery key locks.
func (k Keyring) KeySlots() []vault.Slot { return k.slotsOf(vault.KindKey) }

func (k Keyring) slotsOf(kind string) []vault.Slot {
	var out []vault.Slot
	for _, s := range k.Slots {
		if s.Kind == kind {
			out = append(out, s)
		}
	}
	return out
}

// Lock builds the slots of a master secret: the password's, and the recovery
// key's if there is one.
func (k *Keyring) Lock(master, password string) error {
	slots := []vault.Slot{}
	if password != "" {
		pw, err := vault.PasswordSlot(master, password)
		if err != nil {
			return err
		}
		slots = append(slots, pw)
	}
	if k.Recovery != nil {
		key, err := vault.KeySlot(master, k.Recovery.Public)
		if err != nil {
			return err
		}
		slots = append(slots, key)
	}
	k.Slots = slots
	return nil
}

// Relock replaces the password lock, keeping the rest.
func (k *Keyring) Relock(master, password string) error {
	pw, err := vault.PasswordSlot(master, password)
	if err != nil {
		return err
	}
	k.Slots = append([]vault.Slot{pw}, k.KeySlots()...)
	return nil
}

// SetPrevious keeps prev, the master secret being replaced, sealed by master.
func (k *Keyring) SetPrevious(prev, master string) error {
	sealed, err := EncryptBytes([]byte(prev), master)
	if err != nil {
		return err
	}
	k.Previous = sealed
	return nil
}

// PreviousMaster is the master secret being replaced, if there is one.
func (k Keyring) PreviousMaster(master string) (string, error) {
	if len(k.Previous) == 0 {
		return "", nil
	}
	prev, err := DecryptBytes(k.Previous, master)
	if err != nil {
		return "", fmt.Errorf("the previous master secret does not open: %w", err)
	}
	return string(prev), nil
}
