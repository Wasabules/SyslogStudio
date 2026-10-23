package storage

import "testing"

// Deleting the last destination leaves the store file behind holding nothing.
// If HasAny tested for the file, the "credentials are stored in the clear"
// warning would stay on screen forever with nothing left to protect.
func TestSecretStore_HasAnyCountsEntriesNotFiles(t *testing.T) {
	dir := t.TempDir()
	s := NewSecretStore(dir)

	if s.HasAny() {
		t.Fatal("a fresh store reports credentials")
	}
	if err := s.Set("sink-1", "webhook|https://example.com", "tok"); err != nil {
		t.Fatalf("set: %v", err)
	}
	if !s.HasAny() {
		t.Fatal("a stored credential is not reported")
	}
	if got := s.Get("sink-1", "webhook|https://example.com"); got != "tok" {
		t.Fatalf("Get returned %q", got)
	}
	// Bound to its destination: the same id at another URL gets nothing.
	if got := s.Get("sink-1", "webhook|https://evil.example"); got != "" {
		t.Fatalf("credential leaked to another destination: %q", got)
	}

	if err := s.Delete("sink-1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if s.HasAny() {
		t.Fatal("an emptied store still reports credentials")
	}

	// A reopened store must agree, so the warning does not come back on restart.
	if NewSecretStore(dir).HasAny() {
		t.Fatal("a reopened empty store reports credentials")
	}
}

// Changing the password, or turning encryption off, set the new password and
// then rewrote the store — which the new password could not read. The
// credentials stayed under the old one, and every destination lost its
// password. Rekey reads under the old password and writes under the new one.
func TestSecretStore_RekeyCarriesTheCredentials(t *testing.T) {
	dir := t.TempDir()
	const dest = "webhook|https://example.com"
	s := NewSecretStore(dir)
	if err := s.Set("sink-1", dest, "tok"); err != nil {
		t.Fatal(err)
	}
	for _, password := range []string{"first password", "second password", "", "third password"} {
		if err := s.Rekey(password); err != nil {
			t.Fatalf("rekey to %q: %v", password, err)
		}
		if s.IsEncrypted() != (password != "") {
			t.Fatalf("after a rekey to %q the store is encrypted=%v", password, s.IsEncrypted())
		}
		reopened := NewSecretStore(dir)
		reopened.SetPassword(password)
		if got := reopened.Get("sink-1", dest); got != "tok" {
			t.Fatalf("after a rekey to %q the credential reads %q", password, got)
		}
	}

	// A store that cannot be read keeps its password: rekeying it would make
	// it unreadable for good.
	locked := NewSecretStore(dir)
	locked.SetPassword("wrong password")
	if err := locked.Rekey("another"); err == nil {
		t.Fatal("a store read with the wrong password was rekeyed")
	}
	reopened := NewSecretStore(dir)
	reopened.SetPassword("third password")
	if got := reopened.Get("sink-1", dest); got != "tok" {
		t.Fatalf("a refused rekey changed the store: %q", got)
	}
}
