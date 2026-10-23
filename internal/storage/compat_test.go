package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"SyslogStudio/internal/models"
)

// A database encrypted by v1.6.1 — written by that version's own code, see
// testdata/compat — opens with its password, and again after this version
// has closed it.
func TestCompat_V161DatabaseOpens(t *testing.T) {
	src := filepath.Join("testdata", "compat", "v1.6.1")
	var m struct {
		Password   string   `json:"password"`
		MessageIDs []string `json:"messageIds"`
	}
	raw, err := os.ReadFile(filepath.Join(src, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	enc, err := os.ReadFile(filepath.Join(src, "logs.db.enc"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "logs.db")
	if err := os.WriteFile(path+".enc", enc, 0o600); err != nil {
		t.Fatal(err)
	}
	for round := 0; round < 2; round++ {
		ls, err := NewLogStore(models.StorageConfig{Enabled: true, Path: path, EncryptionEnabled: true}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if !ls.IsLocked() {
			t.Fatal("the v1.6.1 database does not open locked")
		}
		if err := ls.UnlockAndOpen(m.Password); err != nil {
			t.Fatalf("round %d: the v1.6.1 database does not unlock: %v", round, err)
		}
		ls.WaitReady()
		res := ls.QueryMessages(models.QueryOptions{Page: 1, PageSize: 100, SortField: "timestamp", SortDir: "asc"})
		if res.Total != len(m.MessageIDs) || res.Messages[0].ID != m.MessageIDs[0] {
			t.Fatalf("round %d: %d messages, first %v; want %d", round, res.Total, res.Messages, len(m.MessageIDs))
		}
		ls.Close()
	}
}
