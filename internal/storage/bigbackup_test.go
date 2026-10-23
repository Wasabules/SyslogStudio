package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"SyslogStudio/internal/backup"
	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/vault"
)

// How backups behave on a database of real size, while messages keep
// arriving through the store's own write path. Not part of the suite:
//
//	SYSLOGSTUDIO_BIGDB=1000000 go test -run TestBigBackup -v -timeout 60m ./internal/storage
//
// SYSLOGSTUDIO_BIGDB_DIR keeps the files on the disk to be measured.
func TestBigBackup(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("SYSLOGSTUDIO_BIGDB"))
	if n == 0 {
		t.Skip("set SYSLOGSTUDIO_BIGDB to a number of messages")
	}
	dir := os.Getenv("SYSLOGSTUDIO_BIGDB_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	report := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }
	const rate = 2000 // messages per second arriving meanwhile
	// Ids of their own to the messages of this run: a database reused from a
	// previous run already holds that run's.
	run := time.Now().UnixNano()

	path := filepath.Join(dir, "big-backup.db")
	// SYSLOGSTUDIO_BIGDB_REUSE starts again from the database a previous run
	// left in SYSLOGSTUDIO_BIGDB_DIR, rather than writing a million messages.
	reuse := os.Getenv("SYSLOGSTUDIO_BIGDB_REUSE") != ""
	if _, err := os.Stat(path); err != nil || !reuse {
		for _, s := range []string{"", "-wal", "-shm"} {
			os.Remove(path + s)
		}
		db := openBig(t, path, "INCREMENTAL")
		took := fill(t, db, n, 30)
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		db.Close()
		report("\n== %d messages written in %s, file %.0f MB", n, took.Round(time.Millisecond), fileMB(path))
	}

	ls, err := NewLogStore(models.StorageConfig{Enabled: true, Path: path}, event.NewMockEventEmitter())
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	ls.WaitReady()
	report("store open, search index ready in %s", time.Since(start).Round(time.Millisecond))
	before, _, _ := ls.Span()
	// As a restore does: what is written after this goes over to the restored
	// database.
	mark := ls.Mark()

	// Messages arriving through the write buffer, as the receiver hands them
	// over; the deepest the buffer gets says how long writes were held up.
	var buffered atomic.Int64
	var deepest atomic.Int64
	stop := make(chan struct{})
	var wg sync.WaitGroup
	arrive := func() {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tick := time.NewTicker(50 * time.Millisecond)
			defer tick.Stop()
			for i := n + 1_000_000; ; {
				select {
				case <-stop:
					return
				case <-tick.C:
					now := time.Now()
					for j := 0; j < rate/20; j++ {
						i++
						m := bigMessage(i, now)
						m.ID = fmt.Sprintf("%d-%d", run, i)
						ls.BufferMessage(m)
					}
					buffered.Add(int64(rate / 20))
					ls.mu.Lock()
					if d := int64(len(ls.buffer)); d > deepest.Load() {
						deepest.Store(d)
					}
					ls.mu.Unlock()
				}
			}
		}()
	}
	arrive()

	// A write straight to the database every 100 ms while the snapshot runs:
	// how long the longest one waits, and whether any fails.
	var probeWorst atomic.Int64
	var probeFailed, probes atomic.Int64
	probeStop := make(chan struct{})
	var probeWG sync.WaitGroup
	probeWG.Add(1)
	go func() {
		defer probeWG.Done()
		tick := time.NewTicker(100 * time.Millisecond)
		defer tick.Stop()
		for i := 0; ; i++ {
			select {
			case <-probeStop:
				return
			case <-tick.C:
				m := bigMessage(i, time.Now())
				m.ID = fmt.Sprintf("probe-%d-%d", run, i)
				start := time.Now()
				_, err := ls.handle().Exec("INSERT INTO messages (id, timestamp, received_at, severity, severity_label, facility, facility_label) VALUES (?, ?, ?, 6, 'Info', 1, 'user')",
					m.ID, m.Timestamp.UTC().Format(time.RFC3339Nano), m.Timestamp.UTC().Format(time.RFC3339Nano))
				if d := time.Since(start).Microseconds(); d > probeWorst.Load() {
					probeWorst.Store(d)
				}
				probes.Add(1)
				if err != nil {
					probeFailed.Add(1)
					report("probe write failed after %s: %v", time.Since(start).Round(time.Millisecond), err)
				}
			}
		}
	}()

	snap := filepath.Join(dir, "big-backup.snapshot.db")
	removeAll := func(p string) {
		for _, s := range []string{"", "-wal", "-shm", "-journal", ".part"} {
			os.Remove(p + s)
		}
	}
	removeAll(snap)
	start = time.Now()
	if err := ls.Snapshot(context.Background(), snap); err != nil {
		t.Fatal(err)
	}
	snapTook := time.Since(start)
	close(probeStop)
	probeWG.Wait()
	report("snapshot: %s, %.0f MB, deepest write buffer %d messages (%.1f s of arrivals); direct writes: %d, longest %s, %d failed",
		snapTook.Round(time.Millisecond), fileMB(snap), deepest.Load(), float64(deepest.Load())/rate,
		probes.Load(), (time.Duration(probeWorst.Load()) * time.Microsecond).Round(time.Millisecond), probeFailed.Load())

	master := vault.NewMaster()
	slot, err := vault.PasswordSlot(master, "big backup password")
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(dir, "big-backups")
	os.RemoveAll(outDir)
	start = time.Now()
	f, err := backup.Write(snap, outDir, time.Now(), false, backup.Lock{Master: master, Slots: []vault.Slot{slot}}, "bench", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	report("encrypt and read back: %s, backup %.0f MB", time.Since(start).Round(time.Millisecond), f.SizeMB)

	restored := filepath.Join(dir, "big-backup.restore.db")
	removeAll(restored)
	start = time.Now()
	if _, err := backup.Open(f.Path, backup.Credentials{Password: "big backup password"}, restored, nil); err != nil {
		t.Fatal(err)
	}
	report("open (decrypt): %s", time.Since(start).Round(time.Millisecond))

	start = time.Now()
	view, err := OpenSnapshot(restored)
	if err != nil {
		t.Fatal(err)
	}
	report("check and open to read: %s", time.Since(start).Round(time.Millisecond))
	for _, q := range []struct {
		name string
		opts models.QueryOptions
	}{
		{"newest page", models.QueryOptions{Page: 1, PageSize: 200, SortField: "timestamp", SortDir: "desc"}},
		{"full-text page", models.QueryOptions{Page: 1, PageSize: 200, Filter: models.FilterCriteria{Search: "timed out", SearchMode: "fts"}}},
	} {
		start = time.Now()
		res := view.QueryMessages(q.opts)
		report("read the backup, %s: %s (%d of %d)", q.name, time.Since(start).Round(time.Millisecond), len(res.Messages), res.Total)
	}
	view.Close()

	deepest.Store(0)
	start = time.Now()
	if err := ls.Replace(restored, mark); err != nil {
		t.Fatal(err)
	}
	report("replace: %s, deepest write buffer %d messages", time.Since(start).Round(time.Millisecond), deepest.Load())

	count := func() (int64, error) {
		var c int64
		err := ls.handle().QueryRow("SELECT COUNT(*) FROM messages").Scan(&c)
		return c, err
	}
	for i := 0; i < 5; i++ {
		time.Sleep(time.Second)
		c, err := count()
		ls.mu.Lock()
		pending := len(ls.buffer)
		ls.mu.Unlock()
		report("  +%ds: %d messages (%v), %d waiting", i+1, c, err, pending)
	}
	close(stop)
	wg.Wait()
	for {
		ls.flushWaiting()
		ls.mu.Lock()
		pending := len(ls.buffer)
		ls.mu.Unlock()
		if pending == 0 {
			break
		}
	}
	after, err := count()
	if err != nil {
		t.Fatalf("counting after the restore: %v", err)
	}
	after -= probes.Load()
	snapCount := func() int64 {
		v, err := OpenSnapshot(snap)
		if err != nil {
			t.Fatal(err)
		}
		defer v.Close()
		c, _, _ := v.Span()
		return c
	}()
	// After the replace the database is the snapshot, plus everything that
	// arrived after the mark: nothing received is lost by the restore.
	report("messages: %d before, %d in the snapshot, %d arrived meanwhile, %d after the restore",
		before, snapCount, buffered.Load(), after)
	if after != before+buffered.Load() {
		t.Errorf("after the restore %d messages, want the %d before and the %d that arrived", after, before, buffered.Load())
	}
	ls.Close()
	removeAll(snap)
	if !reuse {
		removeAll(path)
	}
	os.RemoveAll(outDir)
}
