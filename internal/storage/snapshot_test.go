package storage

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

func idsOf(t *testing.T, ls *LogStore) map[string]bool {
	t.Helper()
	res := ls.QueryMessages(models.QueryOptions{Page: 1, PageSize: 10000})
	ids := make(map[string]bool, len(res.Messages))
	for _, m := range res.Messages {
		ids[m.ID] = true
	}
	return ids
}

func prefixed(prefix string, from, n int) []models.SyslogMessage {
	var msgs []models.SyslogMessage
	for i := from; i < from+n; i++ {
		m := testMessage(i, "host", "app", "message", models.SevNotice)
		m.ID = fmt.Sprintf("%s-%04d", prefix, i)
		msgs = append(msgs, m)
	}
	return msgs
}

// A snapshot is taken while messages keep being written: it is a whole
// database, and the writes go on beside it, none lost.
func TestSnapshot_WhileWriting(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	ls.WaitReady()
	seed(t, ls, prefixed("before", 0, 2000)...)

	var written atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			ls.BufferMessage(prefixed("during", i, 1)[0])
			written.Add(1)
			if i%50 == 0 {
				ls.flush()
			}
			time.Sleep(200 * time.Microsecond)
		}
	}()
	snap := filepath.Join(t.TempDir(), "snap.db")
	err := ls.Snapshot(context.Background(), snap)
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}
	ls.flushWaiting()

	view, err := OpenSnapshot(snap)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()
	if n, _, _ := view.Span(); n < 2000 {
		t.Fatalf("the snapshot holds %d messages, want at least the 2000 written before it", n)
	}
	if n, _, _ := ls.Span(); n != 2000+written.Load() {
		t.Fatalf("the database holds %d messages, want %d: writes were lost during the snapshot", n, 2000+written.Load())
	}
}

// A snapshot opened to be read refuses to be written, and searches like the
// database it came from.
func TestOpenSnapshot_ReadOnly(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	ls.WaitReady()
	seed(t, ls, testMessage(1, "alpha", "sshd", "Échec de connexion", models.SevError))
	snap := filepath.Join(t.TempDir(), "snap.db")
	if err := ls.Snapshot(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	view, err := OpenSnapshot(snap)
	if err != nil {
		t.Fatal(err)
	}
	defer view.Close()
	if err := view.InsertMessages(prefixed("x", 0, 1)); err == nil {
		t.Error("a snapshot opened to be read accepted a write")
	}
	if _, err := view.handle().Exec("DELETE FROM messages"); err == nil {
		t.Error("the connection to a snapshot opened to be read can write")
	}
	if n, _, _ := view.Span(); n != 1 {
		t.Errorf("the snapshot holds %d messages after the refused writes, want 1", n)
	}
	res := view.QueryMessages(models.QueryOptions{Page: 1, PageSize: 10,
		Filter: models.FilterCriteria{Search: "echec", SearchMode: "fts"}})
	if res.Total != 1 {
		t.Errorf("a full-text search of the snapshot found %d messages, want 1", res.Total)
	}
	if err := view.Snapshot(context.Background(), filepath.Join(t.TempDir(), "again.db")); err == nil {
		t.Error("a read-only snapshot was copied as if it were the database")
	}
}

// Replacing the database keeps what was written after the mark — received
// while the restore was being prepared — and what waits in the buffer.
func TestReplace_CarriesWhatCameAfterTheMark(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	ls.WaitReady()
	seed(t, ls, prefixed("old", 0, 10)...)
	mark := ls.Mark()
	seed(t, ls, prefixed("meanwhile", 0, 5)...)

	other := newTestStore(t, models.StorageConfig{})
	other.WaitReady()
	seed(t, other, prefixed("backup", 0, 20)...)
	snap := filepath.Join(t.TempDir(), "restore.db")
	if err := other.Snapshot(context.Background(), snap); err != nil {
		t.Fatal(err)
	}

	if err := ls.Replace(snap, mark); err != nil {
		t.Fatal(err)
	}
	ls.WaitReady()
	ids := idsOf(t, ls)
	for _, want := range []string{"backup-0000", "backup-0019", "meanwhile-0000", "meanwhile-0004"} {
		if !ids[want] {
			t.Errorf("%s is missing after the replace", want)
		}
	}
	if ids["old-0000"] || len(ids) != 25 {
		t.Errorf("after the replace the database holds %d messages (old-0000: %v), want the backup's 20 and the 5 after the mark", len(ids), ids["old-0000"])
	}
	if _, err := os.Stat(snap); !os.IsNotExist(err) {
		t.Error("the restored file is still beside the database")
	}

	seed(t, ls, prefixed("after", 0, 1)...)
	if !idsOf(t, ls)["after-0000"] {
		t.Error("the replaced database does not receive")
	}
}

// A file that is not a database replaces nothing.
func TestReplace_RefusesWhatIsNotADatabase(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	ls.WaitReady()
	seed(t, ls, prefixed("kept", 0, 3)...)
	bad := filepath.Join(t.TempDir(), "bad.db")
	if err := os.WriteFile(bad, []byte("not a database at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ls.Replace(bad, ls.Mark()); err == nil {
		t.Fatal("a file that is not a database replaced the database")
	}
	if n, _, _ := ls.Span(); n != 3 {
		t.Fatalf("a refused replace changed the database: %d messages", n)
	}
	seed(t, ls, prefixed("after", 0, 1)...)
	if n, _, _ := ls.Span(); n != 4 {
		t.Error("the store stopped receiving after a refused replace")
	}
}

// A write that waits out the busy timeout — another writer holding the
// database longer than that — used to lose the rows that did not go in while
// the batch counted as stored. The batch is now rolled back and requeued,
// and written once the database is free.
func TestWrite_LockedDatabaseKeepsTheMessages(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	ls.WaitReady()
	other, err := sql.Open("sqlite", dsn(ls.currentConfig().Path))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	conn, err := other.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	for _, m := range prefixed("locked", 0, 3) {
		ls.BufferMessage(m)
	}
	ls.flushWaiting() // waits out the busy timeout, fails, puts the batch back
	ls.mu.Lock()
	waiting := len(ls.buffer)
	ls.mu.Unlock()
	if waiting != 3 {
		t.Fatalf("%d messages wait after a failed write, want the 3 of the batch", waiting)
	}
	conn.ExecContext(context.Background(), "ROLLBACK")
	conn.Close()
	ls.flushWaiting()
	if n, _, _ := ls.Span(); n != 3 {
		t.Fatalf("%d messages stored once the database is free, want 3", n)
	}
}
