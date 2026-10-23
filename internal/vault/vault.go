// Package vault is how SyslogStudio keeps what it encrypts at rest, and the
// keys to it.
//
// Everything encrypted — the database, its backups, the CA, the credentials —
// is encrypted with one master secret, not with the password. The password is
// one of the locks on that secret; a recovery key, a key pair whose private
// half the user keeps elsewhere, is another. A lock is a Slot: the master
// secret wrapped so that one password, or one private key, gets it back.
// Changing the password replaces a slot and rewrites nothing else, and a
// forgotten password is no longer the end of the data when a recovery key
// exists.
//
// Files that travel — backups — carry their slots in their own header, so
// that they open on another machine, after the original disk is gone, with
// the password they were made under or with the recovery key.
//
// The recovery key uses the inbox's hybrid post-quantum suite (ML-KEM-768
// with X25519, RFC 9180 HPKE).
package vault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
)

// Argon2id, as the rest of SyslogStudio derives keys from a password.
const (
	argonTime    = 3
	argonMemory  = 64 * 1024
	argonThreads = 4
	keyLen       = 32
)

var (
	kem  = hpke.MLKEM768X25519()
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()
)

// The kinds of Slot.
const (
	KindPassword = "password"
	KindKey      = "key"
)

var (
	// ErrWrongPassword is a password that opens none of the slots.
	ErrWrongPassword = errors.New("wrong password")
	// ErrNoSlotForKey is a recovery key no slot was made for.
	ErrNoSlotForKey = errors.New("this recovery key does not open this")
)

// masterPrefix marks a master secret made by NewMaster. Installations
// encrypted before vault have their password as their master secret, and
// keep it until the password is next changed.
const masterPrefix = "ssm1:"

// NewMaster makes a master secret: 256 random bits, as text, because the
// stores that encrypt with it take a password.
func NewMaster() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on supported systems
	}
	return masterPrefix + base64.RawStdEncoding.EncodeToString(b)
}

// IsGenerated reports whether a master secret was made by NewMaster, rather
// than being an earlier installation's password.
func IsGenerated(master string) bool {
	return len(master) > len(masterPrefix) && master[:len(masterPrefix)] == masterPrefix
}

// Slot is one lock on a master secret.
type Slot struct {
	Kind string `json:"kind"`
	// A password slot: the Argon2id salt, and the AES-GCM nonce the master
	// secret was sealed with under the derived key.
	Salt  []byte `json:"salt,omitempty"`
	Nonce []byte `json:"nonce,omitempty"`
	// A key slot: which recovery key it was made for.
	KeyID   string `json:"keyId,omitempty"`
	Created string `json:"created,omitempty"`
	Wrapped []byte `json:"wrapped"`
}

var passwordSlotAAD = []byte("SyslogStudio vault password slot v1")

func random(n int) []byte {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// deriveKey is Argon2id of a secret and a salt.
func deriveKey(secret string, salt []byte) []byte {
	return argon2.IDKey([]byte(secret), salt, argonTime, argonMemory, argonThreads, keyLen)
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// PasswordSlot locks master with a password.
func PasswordSlot(master, password string) (Slot, error) {
	salt := random(16)
	g, err := gcm(deriveKey(password, salt))
	if err != nil {
		return Slot{}, err
	}
	nonce := random(g.NonceSize())
	return Slot{
		Kind: KindPassword, Salt: salt, Nonce: nonce, Created: now(),
		Wrapped: g.Seal(nil, nonce, []byte(master), passwordSlotAAD),
	}, nil
}

func keySlotInfo(keyID string) []byte {
	return []byte("SyslogStudio vault key slot v1 " + keyID)
}

// KeySlot locks master with the public half of a recovery key.
func KeySlot(master string, pub []byte) (Slot, error) {
	pk, err := kem.NewPublicKey(pub)
	if err != nil {
		return Slot{}, fmt.Errorf("not a recovery public key: %w", err)
	}
	id := KeyID(pub)
	ct, err := hpke.Seal(pk, kdf, aead, keySlotInfo(id), []byte(master))
	if err != nil {
		return Slot{}, err
	}
	return Slot{Kind: KindKey, KeyID: id, Created: now(), Wrapped: ct}, nil
}

// OpenWithPassword gets the master secret back from the first password slot
// the password opens.
func OpenWithPassword(slots []Slot, password string) (string, error) {
	for _, s := range slots {
		if s.Kind != KindPassword {
			continue
		}
		g, err := gcm(deriveKey(password, s.Salt))
		if err != nil {
			return "", err
		}
		if master, err := g.Open(nil, s.Nonce, s.Wrapped, passwordSlotAAD); err == nil {
			return string(master), nil
		}
	}
	return "", ErrWrongPassword
}

// OpenWithKey gets the master secret back with a recovery key's private half.
func OpenWithKey(slots []Slot, priv []byte) (string, error) {
	k, err := kem.NewPrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("not a recovery key: %w", err)
	}
	id := KeyID(k.PublicKey().Bytes())
	for _, s := range slots {
		if s.Kind != KindKey || s.KeyID != id {
			continue
		}
		master, err := hpke.Open(k, kdf, aead, keySlotInfo(id), s.Wrapped)
		if err != nil {
			return "", fmt.Errorf("the recovery key slot does not open: damaged, or altered: %w", err)
		}
		return string(master), nil
	}
	return "", ErrNoSlotForKey
}

// --- recovery keys --------------------------------------------------------------

// KeyID names a recovery key by its public half: what a slot and a key file
// show, so the right file can be found.
func KeyID(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

const recoveryPEMType = "SYSLOGSTUDIO RECOVERY KEY"

// GenerateRecoveryKey makes a recovery key: the file to give the user, and
// the public half to lock with.
func GenerateRecoveryKey() (file, pub []byte, id string, err error) {
	k, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, "", err
	}
	priv, err := k.Bytes()
	if err != nil {
		return nil, nil, "", err
	}
	pub = k.PublicKey().Bytes()
	id = KeyID(pub)
	file = pem.EncodeToMemory(&pem.Block{
		Type: recoveryPEMType,
		Headers: map[string]string{
			"Key-ID":  id,
			"Created": now(),
			"Comment": "Keep this file away from the computer it protects. With it, SyslogStudio data locked to this key opens without the password.",
		},
		Bytes: priv,
	})
	return file, pub, id, nil
}

// ParseRecoveryKey reads a recovery key file, and checks it is whole.
func ParseRecoveryKey(file []byte) (priv []byte, id string, err error) {
	block, _ := pem.Decode(bytes.TrimSpace(file))
	if block == nil || block.Type != recoveryPEMType {
		return nil, "", errors.New("not a SyslogStudio recovery key file")
	}
	k, err := kem.NewPrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("the recovery key file is damaged: %w", err)
	}
	id = KeyID(k.PublicKey().Bytes())
	if named := block.Headers["Key-ID"]; named != "" && named != id {
		return nil, "", errors.New("the recovery key file is damaged: its key does not match its name")
	}
	return block.Bytes, id, nil
}
