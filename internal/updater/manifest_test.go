package updater

import "testing"

func TestParseManifestVersion(t *testing.T) {
	manifest := []byte("version v1.2.3\nabc  SyslogStudio-linux-amd64\n")
	if v := parseManifestVersion(manifest); v != "v1.2.3" {
		t.Errorf("got %q, want v1.2.3", v)
	}
	if v := parseManifestVersion([]byte("abc  file\n")); v != "" {
		t.Errorf("expected empty version when the line is absent, got %q", v)
	}
}

func TestParseChecksum_VersionLineAndDuplicates(t *testing.T) {
	manifest := []byte(
		"version v1.2.3\n" +
			"h1  SyslogStudio-linux-amd64\n" +
			"h2  SyslogStudio-windows-amd64.exe\n")

	if sum, err := parseChecksum(manifest, "SyslogStudio-linux-amd64"); err != nil || sum != "h1" {
		t.Errorf("got (%q, %v), want (h1, nil)", sum, err)
	}
	// The "version" line must not be mistaken for an asset checksum.
	if _, err := parseChecksum(manifest, "v1.2.3"); err == nil {
		t.Error("version line should not match as an asset")
	}
	// Duplicate entries for the same asset are rejected.
	dup := []byte("h1  SyslogStudio-linux-amd64\nh2  SyslogStudio-linux-amd64\n")
	if _, err := parseChecksum(dup, "SyslogStudio-linux-amd64"); err == nil {
		t.Error("duplicate entries should be rejected")
	}
}
