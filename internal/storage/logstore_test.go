package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
)

// LogStore is the only component that talks to SQLite — schema, FTS5 triggers,
// pagination, retention and the encrypt-on-close cycle all live here — and it
// had no test at all, so a SQLite driver upgrade was landing unverified. These
// exercise the queries through the real engine rather than mocking it away.

// newTestStore opens a LogStore on a throwaway database and returns it with a
// cleanup that closes it exactly once.
func newTestStore(t *testing.T, cfg models.StorageConfig) *LogStore {
	t.Helper()
	if cfg.Path == "" {
		cfg.Path = filepath.Join(t.TempDir(), "logs.db")
	}
	cfg.Enabled = true

	ls, err := NewLogStore(cfg, event.NewMockEventEmitter())
	if err != nil {
		t.Fatalf("NewLogStore: %v", err)
	}
	// Close is idempotent — it returns early once the handle is nil — so tests
	// that close the store themselves can still rely on this. It must run, and
	// run before t.TempDir's own cleanup: Windows refuses to unlink a database
	// file that SQLite still holds open.
	t.Cleanup(func() { ls.Close() })
	return ls
}

func testMessage(i int, host, app, text string, sev models.Severity) models.SyslogMessage {
	now := time.Now().Add(-time.Duration(i) * time.Minute)
	return models.SyslogMessage{
		ID:            fmt.Sprintf("msg-%04d", i),
		Timestamp:     now,
		ReceivedAt:    now,
		Severity:      sev,
		SeverityLabel: models.SeverityToLabel(sev),
		Facility:      models.FacUser,
		FacilityLabel: models.FacilityToLabel(models.FacUser),
		Hostname:      host,
		AppName:       app,
		Message:       text,
		RawMessage:    "<14>1 - " + host + " " + app + " - - - " + text,
		SourceIP:      "192.0.2.1",
		Protocol:      "UDP",
	}
}

// seed buffers messages and forces them to disk, so the assertions that follow
// read committed rows rather than the in-memory buffer.
func seed(t *testing.T, ls *LogStore, msgs ...models.SyslogMessage) {
	t.Helper()
	for _, m := range msgs {
		ls.BufferMessage(m)
	}
	ls.flush()
}

func TestLogStore_RoundTrip(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	seed(t, ls,
		testMessage(0, "alpha", "sshd", "connection refused", models.SevError),
		testMessage(1, "beta", "nginx", "request served", models.SevInformational),
	)

	res := ls.QueryMessages(models.QueryOptions{Page: 1, PageSize: 50})
	if res.Total != 2 {
		t.Fatalf("Total = %d, want 2", res.Total)
	}
	if len(res.Messages) != 2 {
		t.Fatalf("returned %d messages, want 2", len(res.Messages))
	}

	// Default order is timestamp DESC, and testMessage(0) is the most recent.
	got := res.Messages[0]
	if got.ID != "msg-0000" {
		t.Errorf("first row ID = %q, want msg-0000 (newest first)", got.ID)
	}
	if got.Hostname != "alpha" || got.AppName != "sshd" || got.Message != "connection refused" {
		t.Errorf("round-tripped fields wrong: %+v", got)
	}
	if got.Severity != models.SevError || got.SeverityLabel != "Error" {
		t.Errorf("severity = %d/%q, want %d/Error", got.Severity, got.SeverityLabel, models.SevError)
	}
	// Timestamps go through RFC3339Nano text; they must survive the trip.
	if got.Timestamp.IsZero() || got.ReceivedAt.IsZero() {
		t.Errorf("timestamps did not round-trip: %+v / %+v", got.Timestamp, got.ReceivedAt)
	}
}

func TestLogStore_InsertIsIdempotent(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	m := testMessage(0, "alpha", "sshd", "duplicate", models.SevError)
	// The flush statement is INSERT OR IGNORE on a TEXT primary key: replaying
	// the same message (a retried batch) must not double-count it.
	seed(t, ls, m)
	seed(t, ls, m)

	if got := ls.QueryMessages(models.QueryOptions{Page: 1, PageSize: 10}).Total; got != 1 {
		t.Fatalf("Total = %d after inserting the same ID twice, want 1", got)
	}
}

func TestLogStore_Filters(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	seed(t, ls,
		testMessage(0, "alpha", "sshd", "connection refused", models.SevError),
		testMessage(1, "beta", "nginx", "request served", models.SevInformational),
		testMessage(2, "alpha", "nginx", "upstream timed out", models.SevWarning),
	)

	tests := []struct {
		name   string
		filter models.FilterCriteria
		want   int
	}{
		{"no filter", models.FilterCriteria{}, 3},
		{"severity", models.FilterCriteria{Severities: []int{int(models.SevError)}}, 1},
		{"severity set", models.FilterCriteria{Severities: []int{int(models.SevError), int(models.SevWarning)}}, 2},
		{"hostname substring", models.FilterCriteria{Hostname: "alph"}, 2},
		{"appName", models.FilterCriteria{AppName: "nginx"}, 2},
		{"sourceIP", models.FilterCriteria{SourceIP: "192.0.2"}, 3},
		{"no match", models.FilterCriteria{Hostname: "gamma"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := ls.QueryMessages(models.QueryOptions{Filter: tt.filter, Page: 1, PageSize: 50})
			if res.Total != tt.want {
				t.Errorf("Total = %d, want %d", res.Total, tt.want)
			}
		})
	}
}

func TestLogStore_SearchModes(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	seed(t, ls,
		testMessage(0, "alpha", "sshd", "connection refused by peer", models.SevError),
		testMessage(1, "beta", "nginx", "upstream timed out", models.SevWarning),
	)
	// The FTS index is rebuilt in the background; the triggers keep it in sync
	// for these inserts, but wait for the rebuild so the state is settled.
	<-ls.ftsReadyCh

	tests := []struct {
		name   string
		filter models.FilterCriteria
		want   int
	}{
		// Text mode escapes the query into prefix terms joined by AND.
		{"text single term", models.FilterCriteria{Search: "refused", SearchMode: "text"}, 1},
		{"text two terms AND", models.FilterCriteria{Search: "connection refused", SearchMode: "text"}, 1},
		{"text terms in different rows", models.FilterCriteria{Search: "refused upstream", SearchMode: "text"}, 0},
		{"text prefix", models.FilterCriteria{Search: "connec", SearchMode: "text"}, 1},
		// FTS mode passes the query through, so operators are available.
		{"fts OR", models.FilterCriteria{Search: "refused OR upstream", SearchMode: "fts"}, 2},
		// Regex is applied in Go after the SQL pass.
		{"regex", models.FilterCriteria{Search: "refus(ed|al)", SearchMode: "regex"}, 1},
		{"regex is case-insensitive", models.FilterCriteria{Search: "REFUSED", SearchMode: "regex"}, 1},
		{"regex no match", models.FilterCriteria{Search: "^nothing", SearchMode: "regex"}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := ls.QueryMessages(models.QueryOptions{Filter: tt.filter, Page: 1, PageSize: 50})
			if res.Total != tt.want {
				t.Errorf("Total = %d, want %d", res.Total, tt.want)
			}
		})
	}
}

// A malformed FTS query must not take the process down: FTS5 rejects it and the
// store reports no rows.
func TestLogStore_MalformedFTSQueryIsSurvivable(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	seed(t, ls, testMessage(0, "alpha", "sshd", "hello", models.SevError))
	<-ls.ftsReadyCh

	res := ls.QueryMessages(models.QueryOptions{
		Filter:   models.FilterCriteria{Search: `"unbalanced AND (`, SearchMode: "fts"},
		Page:     1,
		PageSize: 10,
	})
	if len(res.Messages) != 0 {
		t.Errorf("malformed FTS query returned %d rows, want 0", len(res.Messages))
	}
}

func TestLogStore_SortAndPagination(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	var msgs []models.SyslogMessage
	for i := 0; i < 25; i++ {
		msgs = append(msgs, testMessage(i, fmt.Sprintf("host-%02d", i), "app", "line", models.SevInformational))
	}
	seed(t, ls, msgs...)

	first := ls.QueryMessages(models.QueryOptions{Page: 1, PageSize: 10, SortField: "hostname", SortDir: "asc"})
	if first.Total != 25 || len(first.Messages) != 10 {
		t.Fatalf("page 1: Total=%d len=%d, want 25/10", first.Total, len(first.Messages))
	}
	if first.Messages[0].Hostname != "host-00" {
		t.Errorf("ascending sort: first hostname = %q, want host-00", first.Messages[0].Hostname)
	}

	last := ls.QueryMessages(models.QueryOptions{Page: 3, PageSize: 10, SortField: "hostname", SortDir: "asc"})
	if len(last.Messages) != 5 {
		t.Errorf("page 3 returned %d rows, want the remaining 5", len(last.Messages))
	}

	// An unknown sort field must fall back to timestamp, not reach the SQL.
	fallback := ls.QueryMessages(models.QueryOptions{Page: 1, PageSize: 5, SortField: "hostname; DROP TABLE messages"})
	if fallback.Total != 25 {
		t.Errorf("unknown sort field: Total = %d, want 25 (fallback, table intact)", fallback.Total)
	}

	// Past the end is empty, not an error.
	beyond := ls.QueryMessages(models.QueryOptions{Page: 99, PageSize: 10})
	if len(beyond.Messages) != 0 {
		t.Errorf("page 99 returned %d rows, want 0", len(beyond.Messages))
	}
}

func TestLogStore_QueryGroups(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	seed(t, ls,
		testMessage(0, "alpha", "sshd", "a", models.SevError),
		testMessage(1, "alpha", "nginx", "b", models.SevError),
		testMessage(2, "beta", "nginx", "c", models.SevWarning),
	)

	groups := ls.QueryGroups(models.FilterCriteria{}, "hostname")
	counts := map[string]int{}
	for _, g := range groups {
		counts[g.Key] = g.Count
	}
	if counts["alpha"] != 2 || counts["beta"] != 1 {
		t.Errorf("hostname groups = %v, want alpha:2 beta:1", counts)
	}
	// Ordered by count descending.
	if len(groups) > 0 && groups[0].Key != "alpha" {
		t.Errorf("first group = %q, want alpha (highest count first)", groups[0].Key)
	}

	if got := ls.QueryGroups(models.FilterCriteria{}, "severity"); len(got) != 2 {
		t.Errorf("severity groups = %d, want 2", len(got))
	}
	// Anything outside the allowlist is refused rather than interpolated.
	if got := ls.QueryGroups(models.FilterCriteria{}, "message; DROP TABLE messages"); got != nil {
		t.Errorf("group by an unlisted field returned %v, want nil", got)
	}
}

func TestLogStore_RetentionByCount(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{MaxMessages: 10})
	var msgs []models.SyslogMessage
	for i := 0; i < 30; i++ {
		msgs = append(msgs, testMessage(i, "host", "app", "line", models.SevInformational))
	}
	seed(t, ls, msgs...)

	ls.runCleanup()

	res := ls.QueryMessages(models.QueryOptions{Page: 1, PageSize: 50})
	if res.Total != 10 {
		t.Fatalf("Total = %d after trimming to MaxMessages=10, want 10", res.Total)
	}
	// testMessage(i) goes further into the past as i grows, so the survivors
	// must be the low indices.
	for _, m := range res.Messages {
		if m.ID > "msg-0009" {
			t.Errorf("kept %s, but the oldest rows should have been trimmed", m.ID)
		}
	}
}

func TestLogStore_RetentionByAge(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{RetentionDays: 1})

	old := testMessage(0, "host", "app", "ancient", models.SevInformational)
	old.ID = "msg-old"
	old.Timestamp = time.Now().Add(-72 * time.Hour)
	recent := testMessage(1, "host", "app", "fresh", models.SevInformational)
	recent.ID = "msg-new"
	seed(t, ls, old, recent)

	ls.runCleanup()

	res := ls.QueryMessages(models.QueryOptions{Page: 1, PageSize: 10})
	if res.Total != 1 {
		t.Fatalf("Total = %d after age retention, want 1", res.Total)
	}
	if res.Messages[0].ID != "msg-new" {
		t.Errorf("survivor = %q, want msg-new", res.Messages[0].ID)
	}
}

func TestLogStore_StatsAndClear(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	seed(t, ls,
		testMessage(0, "alpha", "sshd", "a", models.SevError),
		testMessage(1, "beta", "nginx", "b", models.SevWarning),
	)

	stats := ls.GetStats()
	if stats.MessageCount != 2 {
		t.Errorf("MessageCount = %d, want 2", stats.MessageCount)
	}
	if stats.DatabaseSizeMB <= 0 {
		t.Errorf("DatabaseSizeMB = %v, want a positive size", stats.DatabaseSizeMB)
	}
	if stats.OldestTimestamp == "" {
		t.Error("OldestTimestamp is empty")
	}

	if err := ls.ClearAll(); err != nil {
		t.Fatalf("ClearAll: %v", err)
	}
	if got := ls.GetStats().MessageCount; got != 0 {
		t.Errorf("MessageCount = %d after ClearAll, want 0", got)
	}
}

// A disabled store must accept calls and stay inert rather than panic on its
// nil handle — the app runs this way whenever persistence is switched off.
func TestLogStore_DisabledIsInert(t *testing.T) {
	ls, err := NewLogStore(models.StorageConfig{Enabled: false}, event.NewMockEventEmitter())
	if err != nil {
		t.Fatalf("NewLogStore(disabled): %v", err)
	}
	ls.BufferMessage(testMessage(0, "h", "a", "m", models.SevError))
	if got := ls.QueryMessages(models.QueryOptions{Page: 1, PageSize: 10}).Total; got != 0 {
		t.Errorf("Total = %d on a disabled store, want 0", got)
	}
	if got := ls.QueryGroups(models.FilterCriteria{}, "hostname"); got != nil {
		t.Errorf("QueryGroups = %v on a disabled store, want nil", got)
	}
	if got := ls.GetStats().MessageCount; got != 0 {
		t.Errorf("MessageCount = %d on a disabled store, want 0", got)
	}
	if err := ls.Compact(); err != nil {
		t.Errorf("Compact on a disabled store: %v", err)
	}
	ls.Close() // must not panic
}

// The full at-rest cycle: Close encrypts the database and removes the
// plaintext, a new store comes up locked, and the right password reopens it
// with every row intact.
func TestLogStore_EncryptOnCloseAndUnlock(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "logs.db")
	cfg := models.StorageConfig{Enabled: true, Path: dbPath, EncryptionEnabled: true}

	ls, err := NewLogStore(cfg, event.NewMockEventEmitter())
	if err != nil {
		t.Fatalf("NewLogStore: %v", err)
	}
	seed(t, ls, testMessage(0, "alpha", "sshd", "secret payload", models.SevError))
	ls.SetEncryptionPassword("correct horse battery")
	ls.Close()

	if _, err := os.Stat(dbPath); !os.IsNotExist(err) {
		t.Error("plaintext database still present after an encrypted Close")
	}
	if !EncryptedFileExists(dbPath) {
		t.Fatal("no encrypted database was written")
	}

	reopened, err := NewLogStore(cfg, event.NewMockEventEmitter())
	if err != nil {
		t.Fatalf("NewLogStore on the encrypted database: %v", err)
	}
	if !reopened.IsLocked() {
		t.Fatal("store is not locked despite an encrypted database on disk")
	}
	if got := reopened.QueryMessages(models.QueryOptions{Page: 1, PageSize: 10}).Total; got != 0 {
		t.Errorf("a locked store returned %d rows, want 0", got)
	}

	if err := reopened.UnlockAndOpen("wrong password"); err == nil {
		t.Fatal("UnlockAndOpen accepted the wrong password")
	}
	if !reopened.IsLocked() {
		t.Error("store unlocked itself after a failed attempt")
	}

	if err := reopened.UnlockAndOpen("correct horse battery"); err != nil {
		t.Fatalf("UnlockAndOpen with the right password: %v", err)
	}
	defer reopened.Close()
	if reopened.IsLocked() {
		t.Error("store still reports locked after a successful unlock")
	}

	res := reopened.QueryMessages(models.QueryOptions{Page: 1, PageSize: 10})
	if res.Total != 1 {
		t.Fatalf("Total = %d after unlock, want 1", res.Total)
	}
	if res.Messages[0].Message != "secret payload" {
		t.Errorf("recovered message = %q, want %q", res.Messages[0].Message, "secret payload")
	}
}

// BufferMessage drops the oldest entries once the cap is reached, and says so,
// instead of growing until the process dies.
func TestLogStore_WriteBufferIsBounded(t *testing.T) {
	// Lowered for the duration of the test: the branch under test is the same
	// at 80 as at 200000, and the production value would have the flush loop
	// commit 200k rows before the assertion runs.
	restore := maxWriteBuffer
	maxWriteBuffer = 80
	t.Cleanup(func() { maxWriteBuffer = restore })

	ls := newTestStore(t, models.StorageConfig{})

	// Filled in one go: the flush loop ticks every 500ms, so the buffer is well
	// past the cap before anything drains it.
	for i := 0; i < maxWriteBuffer*3; i++ {
		ls.BufferMessage(testMessage(i, "host", "app", "flood", models.SevDebug))
	}

	ls.mu.Lock()
	buffered := len(ls.buffer)
	ls.mu.Unlock()

	if buffered > maxWriteBuffer {
		t.Errorf("buffer holds %d entries, above the %d cap", buffered, maxWriteBuffer)
	}
	// The count is what makes the loss visible in StorageStats; without it the
	// drop would be silent.
	if got := ls.droppedWriteCount(); got == 0 {
		t.Error("DroppedWrites = 0 after overflowing the buffer")
	}
}
