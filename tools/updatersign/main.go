// Command updatersign manages the Ed25519 keypair that authenticates
// SyslogStudio auto-updates, and signs the release checksums manifest.
//
// Usage:
//
//	go run ./tools/updatersign keygen         # print a fresh keypair
//	UPDATER_PRIVATE_KEY=<hex> \
//	  go run ./tools/updatersign sign <file>  # write <file>.sig
//
// The public key (base64) is embedded in the app at
// internal/updater/verify.go (updaterPublicKey); the private key (hex) is
// stored as the GitHub Actions secret UPDATER_PRIVATE_KEY and injected into
// the release workflow. If the secret is unset, `sign` is a no-op so
// unsigned builds still succeed (updates then fall back to SHA-256-only
// integrity, without authenticity).
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: updatersign <keygen|sign> [file]")
		os.Exit(2)
	}
	switch os.Args[1] {
	case "keygen":
		keygen()
	case "sign":
		if len(os.Args) < 3 {
			fmt.Fprintln(os.Stderr, "usage: updatersign sign <file>")
			os.Exit(2)
		}
		sign(os.Args[2])
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		os.Exit(2)
	}
}

// keygen mints a fresh Ed25519 keypair and prints it in a parseable form:
//
//	PUBLIC_KEY=<base64>   -> paste into internal/updater/verify.go
//	PRIVATE_KEY=<hex>     -> store as the UPDATER_PRIVATE_KEY GitHub secret
func keygen() {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fatal("generate key: %v", err)
	}
	fmt.Printf("PUBLIC_KEY=%s\n", base64.StdEncoding.EncodeToString(pub))
	fmt.Printf("PRIVATE_KEY=%s\n", hex.EncodeToString(priv))
}

// sign writes an Ed25519 signature of the given file to <file>.sig, using
// the hex-encoded private key from UPDATER_PRIVATE_KEY. An unset key is not
// an error: signing is skipped so unsigned release builds still succeed.
func sign(path string) {
	keyHex := strings.TrimSpace(os.Getenv("UPDATER_PRIVATE_KEY"))
	if keyHex == "" {
		fmt.Fprintln(os.Stderr, "updatersign: UPDATER_PRIVATE_KEY unset, skipping signature")
		return
	}
	key, err := hex.DecodeString(keyHex)
	if err != nil {
		fatal("decode private key: %v", err)
	}
	if len(key) != ed25519.PrivateKeySize {
		fatal("private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(key))
	}
	data, err := os.ReadFile(path)
	if err != nil {
		fatal("read %s: %v", path, err)
	}
	sig := ed25519.Sign(ed25519.PrivateKey(key), data)
	out := path + ".sig"
	if err := os.WriteFile(out, []byte(base64.StdEncoding.EncodeToString(sig)), 0o644); err != nil {
		fatal("write %s: %v", out, err)
	}
	fmt.Fprintf(os.Stderr, "updatersign: wrote %s\n", out)
}

func fatal(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "updatersign: "+format+"\n", args...)
	os.Exit(1)
}
