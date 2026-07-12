package updater

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestIsNewer(t *testing.T) {
	tests := []struct {
		name    string
		current string
		latest  string
		want    bool
	}{
		{"patch newer", "v1.1.0", "v1.1.1", true},
		{"minor newer", "v1.1.9", "v1.2.0", true},
		{"major newer", "v1.9.9", "v2.0.0", true},
		{"equal", "v1.1.0", "v1.1.0", false},
		{"older", "v1.1.0", "v1.0.9", false},
		{"double-digit minor vs single", "v1.9.0", "v1.10.0", true},
		{"double-digit patch vs single", "v1.1.9", "v1.1.10", true},
		{"current double-digit not older", "v1.10.0", "v1.9.0", false},
		{"no v prefix on both", "1.1.0", "1.2.0", true},
		{"mixed prefix, equal", "1.2.0", "v1.2.0", false},
		{"empty current", "", "v1.0.0", false},
		{"empty latest", "v1.0.0", "", false},
		{"non-semver latest is not newer", "v1.0.0", "banana", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isNewer(tt.current, tt.latest); got != tt.want {
				t.Errorf("isNewer(current=%q, latest=%q) = %v, want %v", tt.current, tt.latest, got, tt.want)
			}
		})
	}
}

func TestDisplayVersion(t *testing.T) {
	cases := map[string]string{"v1.2.3": "1.2.3", "1.2.3": "1.2.3", "V2.0.0": "2.0.0", "": ""}
	for in, want := range cases {
		if got := displayVersion(in); got != want {
			t.Errorf("displayVersion(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseChecksum(t *testing.T) {
	manifest := []byte(
		"abc123  SyslogStudio-windows-amd64.exe\n" +
			"def456 *SyslogStudio-linux-amd64\n" + // binary-mode "*" marker
			"deadbeef  SyslogStudio-macos-universal.dmg\n")

	if sum, err := parseChecksum(manifest, "SyslogStudio-windows-amd64.exe"); err != nil || sum != "abc123" {
		t.Errorf("windows: got (%q, %v), want (abc123, nil)", sum, err)
	}
	if sum, err := parseChecksum(manifest, "SyslogStudio-linux-amd64"); err != nil || sum != "def456" {
		t.Errorf("linux (star marker): got (%q, %v), want (def456, nil)", sum, err)
	}
	if _, err := parseChecksum(manifest, "not-present"); err == nil {
		t.Error("expected an error for a missing asset")
	}
}

func TestVerifyManifestSignature(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	old := updaterPublicKey
	updaterPublicKey = base64.StdEncoding.EncodeToString(pub)
	defer func() { updaterPublicKey = old }()

	manifest := []byte("abc123  asset\n")
	sig := []byte(base64.StdEncoding.EncodeToString(ed25519.Sign(priv, manifest)))

	if err := verifyManifestSignature(manifest, sig); err != nil {
		t.Errorf("valid signature rejected: %v", err)
	}
	if err := verifyManifestSignature([]byte("tampered  asset\n"), sig); err == nil {
		t.Error("tampered manifest accepted")
	}
	if err := verifyManifestSignature(manifest, []byte("not-base64!!")); err == nil {
		t.Error("garbage signature accepted")
	}
}

func TestSignatureEnforcedWithEmbeddedKey(t *testing.T) {
	if !signatureEnforced() {
		t.Error("signature should be enforced: an embedded public key is set")
	}
}
