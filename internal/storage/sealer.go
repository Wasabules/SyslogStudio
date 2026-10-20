package storage

import (
	"bytes"
	"errors"
	"fmt"
)

// Sealer protects a file with something other than the encryption password.
//
// A service starts with nobody there to type a password, yet it has to present
// its TLS key and use its relay credentials. Those cannot be protected by a
// secret that is absent, so they are protected by the operating system instead
// — DPAPI on Windows — together with the access rules on the directory they
// live in. The password-based encryption still wins when a password is set; a
// sealer only replaces what would otherwise be plaintext.
type Sealer interface {
	Seal(plain []byte) ([]byte, error)
	Unseal(sealed []byte) ([]byte, error)
}

// ErrSealed is returned when a sealed file is read by a store that has no
// sealer: a desktop engine pointed at a service's directory, typically.
var ErrSealed = errors.New("this file is sealed for another process and cannot be read here")

// sealedMagic marks a sealed file, so a store without the sealer refuses it
// clearly instead of reporting it as corrupt JSON — and a plaintext file left
// from before sealing was turned on is still read, then sealed on next save.
var sealedMagic = []byte("SYSLOGSTUDIO-SEALED-1\n")

func sealBytes(s Sealer, plain []byte) ([]byte, error) {
	if s == nil {
		return plain, nil
	}
	out, err := s.Seal(plain)
	if err != nil {
		return nil, fmt.Errorf("seal: %w", err)
	}
	return append(append([]byte(nil), sealedMagic...), out...), nil
}

func unsealBytes(s Sealer, raw []byte) ([]byte, error) {
	if !bytes.HasPrefix(raw, sealedMagic) {
		return raw, nil
	}
	if s == nil {
		return nil, ErrSealed
	}
	out, err := s.Unseal(raw[len(sealedMagic):])
	if err != nil {
		return nil, fmt.Errorf("unseal: %w", err)
	}
	return out, nil
}
