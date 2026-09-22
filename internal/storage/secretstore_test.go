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
