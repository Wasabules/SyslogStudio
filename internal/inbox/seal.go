// Package inbox is the sealed inbox: how a service keeps receiving for
// someone whose database is encrypted without ever holding their password.
//
// The service only needs to write what it receives, never to read it back.
// So it seals each batch of messages with a public key (HPKE, RFC 9180), and
// cannot open what it wrote. The private key stays with the window, encrypted
// by the database password like the CA's. Once that password is typed, the
// window collects the batches, opens them, stores the messages in the
// encrypted database and tells the service to delete them. Nothing received
// rests on disk in the clear; a copy of the service's files shows how many
// batches wait, their sizes and dates, and nothing else.
//
// The suite is hybrid post-quantum (ML-KEM-768 with X25519), so what is
// recorded today cannot be opened by whoever breaks one of the two later.
package inbox

import (
	"bytes"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"SyslogStudio/internal/models"
)

var (
	kem  = hpke.MLKEM768X25519()
	kdf  = hpke.HKDFSHA256()
	aead = hpke.AES256GCM()
)

// magic starts every batch: what it is, and in which format.
var magic = []byte("SSINBOX1")

// keyIDLen is how much of the public key's hash names it in each batch.
const keyIDLen = 8

// ErrNotABatch is data that is not a sealed batch at all.
var ErrNotABatch = errors.New("not a sealed inbox batch")

// OtherKeyError is a batch sealed for another key than the one at hand:
// sealed before the key was replaced, or for another window's.
type OtherKeyError struct{ Batch, Key string }

func (e *OtherKeyError) Error() string {
	return fmt.Sprintf("the batch is sealed for key %s, and this key is %s", e.Batch, e.Key)
}

// GenerateKey makes a key pair: the private half for the window to keep
// behind its password, the public half for the service.
func GenerateKey() (priv, pub []byte, err error) {
	k, err := kem.GenerateKey()
	if err != nil {
		return nil, nil, err
	}
	priv, err = k.Bytes()
	if err != nil {
		return nil, nil, err
	}
	return priv, k.PublicKey().Bytes(), nil
}

// PublicKeyOf is the public half of a private key.
func PublicKeyOf(priv []byte) ([]byte, error) {
	k, err := kem.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("read the inbox key: %w", err)
	}
	return k.PublicKey().Bytes(), nil
}

// CheckPublicKey says whether pub is a key batches can be sealed for.
func CheckPublicKey(pub []byte) error {
	if _, err := kem.NewPublicKey(pub); err != nil {
		return fmt.Errorf("not an inbox public key: %w", err)
	}
	return nil
}

func keyIDBytes(pub []byte) []byte {
	sum := sha256.Sum256(pub)
	return sum[:keyIDLen]
}

// KeyID names a public key. It is written in the clear on every batch, so a
// window can tell a batch sealed for another key from a damaged one.
func KeyID(pub []byte) string {
	return hex.EncodeToString(keyIDBytes(pub))
}

// info binds the format and the key a batch names into its encryption: a
// header altered to name another key fails to open.
func info(keyID []byte) []byte {
	return append([]byte("SyslogStudio sealed inbox v1 "), keyID...)
}

// Seal seals messages for the holder of the private half of pub.
func Seal(pub []byte, msgs []models.SyslogMessage) ([]byte, error) {
	pk, err := kem.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("not an inbox public key: %w", err)
	}
	plain, err := json.Marshal(msgs)
	if err != nil {
		return nil, err
	}
	id := keyIDBytes(pub)
	ct, err := hpke.Seal(pk, kdf, aead, info(id), plain)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(magic)+len(id)+len(ct))
	out = append(out, magic...)
	out = append(out, id...)
	return append(out, ct...), nil
}

// Open opens a batch with the private key it was sealed for.
func Open(priv, data []byte) ([]models.SyslogMessage, error) {
	head := len(magic) + keyIDLen
	if len(data) < head || !bytes.HasPrefix(data, magic) {
		return nil, ErrNotABatch
	}
	k, err := kem.NewPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("read the inbox key: %w", err)
	}
	id := data[len(magic):head]
	if mine := keyIDBytes(k.PublicKey().Bytes()); !bytes.Equal(id, mine) {
		return nil, &OtherKeyError{Batch: hex.EncodeToString(id), Key: hex.EncodeToString(mine)}
	}
	plain, err := hpke.Open(k, kdf, aead, info(id), data[head:])
	if err != nil {
		return nil, fmt.Errorf("the batch does not open: damaged, or altered: %w", err)
	}
	var msgs []models.SyslogMessage
	if err := json.Unmarshal(plain, &msgs); err != nil {
		return nil, fmt.Errorf("the batch opened but does not read: %w", err)
	}
	return msgs, nil
}
