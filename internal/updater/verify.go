package updater

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
)

// updaterPublicKey is the base64-encoded Ed25519 public key that authenticates
// the release checksums manifest. Its private counterpart is stored as the
// GitHub Actions secret UPDATER_PRIVATE_KEY and used by tools/updatersign to
// sign the manifest at release time.
//
// An empty key disables authenticity enforcement: downloads are still verified
// against the SHA-256 recorded in the (then unsigned) manifest, but the
// manifest itself is not authenticated. It is a var, not a const, so the
// empty-key branch is not flagged as dead code.
var updaterPublicKey = "u4YO1yjCr9Z2h8/adMVwChfSnudw3/dMGBTUMsjoi74="

// signatureEnforced reports whether a valid manifest signature is required.
func signatureEnforced() bool { return updaterPublicKey != "" }

// verifyManifestSignature verifies a base64 Ed25519 signature over the raw
// manifest bytes using the embedded public key.
func verifyManifestSignature(manifest, sigBase64 []byte) error {
	pub, err := base64.StdEncoding.DecodeString(updaterPublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return errors.New("invalid embedded updater public key")
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(sigBase64)))
	if err != nil {
		return errors.New("invalid signature encoding")
	}
	if !ed25519.Verify(ed25519.PublicKey(pub), manifest, sig) {
		return errors.New("checksums signature verification failed")
	}
	return nil
}
