package storage

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

// How retention and compaction behave on a database of real size, while
// messages keep arriving. Not part of the suite — it builds a database of
// SYSLOGSTUDIO_BIGDB messages (a million is about 600 MB) and takes minutes:
//
//	SYSLOGSTUDIO_BIGDB=1000000 go test -run TestBigDatabase -v -timeout 60m ./internal/storage
//
// SYSLOGSTUDIO_BIGDB_DIR keeps the database somewhere other than a temporary
// directory, on the disk to be measured.

func bigMessage(i int, at time.Time) models.SyslogMessage {
	texts := []string{
		"Failed password for invalid user admin from 203.0.113.%d port %d ssh2",
		"upstream timed out (110: Connection timed out) while reading response header from upstream, client: 10.10.%d.%d",
		"Port GigabitEthernet1/0/%d changed state to up, link-flap counter %d",
		"checkpoint complete: wrote %d buffers (0.7%%); sync files=%d, longest=0.008 s",
		"Échec de connexion : délai dépassé pour 192.168.%d.%d",
	}
	text := fmt.Sprintf(texts[i%len(texts)], i%250, i%65000)
	host := fmt.Sprintf("host-%02d", i%40)
	return models.SyslogMessage{
		ID: strconv.Itoa(i), Timestamp: at, ReceivedAt: at,
		Severity: models.Severity(i % 8), SeverityLabel: models.SeverityToLabel(models.Severity(i % 8)),
		Facility: models.FacUser, FacilityLabel: "user",
		Hostname: host, AppName: []string{"sshd", "nginx", "kernel", "postgres"}[i%4], ProcID: strconv.Itoa(1000 + i%5000),
		Message:    text,
		RawMessage: "<14>1 " + at.UTC().Format(time.RFC3339Nano) + " " + host + " app - - - " + text,
		SourceIP:   fmt.Sprintf("10.0.%d.%d", i%200, i%250), Protocol: "UDP", Version: 1,
	}
}

// writer stands for messages arriving at rate per second, written the way
// the store's flush loop writes them: a transaction every half second.
type writer struct {
	db       *sql.DB
	next     atomic.Int64
	worst    atomic.Int64 // longest write, in microseconds
	failed   atomic.Int64 // messages in writes that failed
	written  atomic.Int64
	stop     chan struct{}
	done     sync.WaitGroup
	interval time.Duration
	batch    int
}

func startWriter(db *sql.DB, first int, rate int) *writer {
	w := &writer{db: db, stop: make(chan struct{}), interval: 500 * time.Millisecond, batch: rate / 2}
	w.next.Store(int64(first))
	w.done.Add(1)
	go func() {
		defer w.done.Done()
		t := time.NewTicker(w.interval)
		defer t.Stop()
		for {
			select {
			case <-w.stop:
				return
			case <-t.C:
				var batch []models.SyslogMessage
				now := time.Now()
				for i := 0; i < w.batch; i++ {
					batch = append(batch, bigMessage(int(w.next.Add(1)), now))
				}
				start := time.Now()
				err := insertMessages(w.db, batch)
				if d := time.Since(start).Microseconds(); d > w.worst.Load() {
					w.worst.Store(d)
				}
				if err != nil {
					w.failed.Add(int64(len(batch)))
				} else {
					w.written.Add(int64(len(batch)))
				}
			}
		}
	}()
	return w
}

func (w *writer) finish() (worst time.Duration, failed, written int64) {
	close(w.stop)
	w.done.Wait()
	return time.Duration(w.worst.Load()) * time.Microsecond, w.failed.Load(), w.written.Load()
}

func fileMB(path string) float64 {
	var total int64
	for _, s := range []string{"", "-wal"} {
		if fi, err := os.Stat(path + s); err == nil {
			total += fi.Size()
		}
	}
	return float64(total) / (1 << 20)
}

func walMB(path string) float64 {
	if fi, err := os.Stat(path + "-wal"); err == nil {
		return float64(fi.Size()) / (1 << 20)
	}
	return 0
}

func openBig(t *testing.T, path, autoVacuum string) *sql.DB {
	t.Helper()
	dsn := path + "?_pragma=journal_mode(wal)&_pragma=synchronous(normal)&_pragma=busy_timeout(5000)" +
		"&_pragma=cache_size(-64000)&_pragma=mmap_size(268435456)&_pragma=temp_store(memory)"
	if autoVacuum != "" {
		// On every connection of the pool, and before the first table.
		dsn += "&_pragma=auto_vacuum(" + autoVacuum + ")"
	}
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(4)
	if err := initSchema(db); err != nil {
		t.Fatal(err)
	}
	return db
}

func fill(t *testing.T, db *sql.DB, n int, days int) time.Duration {
	t.Helper()
	start := time.Now()
	from := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
	step := time.Duration(days) * 24 * time.Hour / time.Duration(n)
	const batch = 5000
	for i := 0; i < n; i += batch {
		var msgs []models.SyslogMessage
		for j := i; j < i+batch && j < n; j++ {
			msgs = append(msgs, bigMessage(j, from.Add(time.Duration(j)*step)))
		}
		if err := insertMessages(db, msgs); err != nil {
			t.Fatal(err)
		}
	}
	return time.Since(start)
}

func TestBigDatabase(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("SYSLOGSTUDIO_BIGDB"))
	if n == 0 {
		t.Skip("set SYSLOGSTUDIO_BIGDB to a number of messages")
	}
	dir := os.Getenv("SYSLOGSTUDIO_BIGDB_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	const rate = 2000 // messages per second arriving meanwhile
	report := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }

	for _, mode := range []string{"NONE", "INCREMENTAL"} {
		path := filepath.Join(dir, "big-"+mode+".db")
		for _, s := range []string{"", "-wal", "-shm"} {
			os.Remove(path + s)
		}
		db := openBig(t, path, mode)
		took := fill(t, db, n, 30)
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
		report("\n== auto_vacuum=%s: %d messages written in %s (%.0f/s), file %.0f MB",
			mode, n, took.Round(time.Millisecond), float64(n)/took.Seconds(), fileMB(path))

		// A history page while nothing else happens.
		q := func() time.Duration {
			start := time.Now()
			var c int
			db.QueryRow("SELECT COUNT(*) FROM messages WHERE timestamp >= ?", time.Now().Add(-7*24*time.Hour).UTC().Format("2006-01-02T15:04:05")).Scan(&c)
			rows, _ := db.Query("SELECT id FROM messages ORDER BY timestamp DESC, rowid DESC LIMIT 200")
			for rows.Next() {
			}
			rows.Close()
			return time.Since(start)
		}
		report("history page at rest: %s", q().Round(time.Millisecond))

		cutoff := time.Now().Add(-23 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05") // about a quarter

		if mode == "NONE" {
			// Today's retention: one DELETE, messages arriving meanwhile.
			w := startWriter(db, n, rate)
			start := time.Now()
			res, err := db.Exec("DELETE FROM messages WHERE timestamp < ?", cutoff)
			took := time.Since(start)
			time.Sleep(600 * time.Millisecond)
			worst, failed, written := w.finish()
			deleted, _ := res.RowsAffected()
			report("one DELETE of %d rows: %s (err %v); writes meanwhile: worst %s, %d lost, %d written; file %.0f MB",
				deleted, took.Round(time.Millisecond), err, worst.Round(time.Millisecond), failed, written, fileMB(path))

			// Today's Compact (and every Close): VACUUM, messages arriving.
			w = startWriter(db, n+10_000_000, rate)
			start = time.Now()
			_, err = db.Exec("VACUUM")
			took = time.Since(start)
			time.Sleep(600 * time.Millisecond)
			worst, failed, written = w.finish()
			report("VACUUM: %s (err %v); writes meanwhile: worst %s, %d lost, %d written; file %.0f MB",
				took.Round(time.Millisecond), err, worst.Round(time.Millisecond), failed, written, fileMB(path))
		} else {
			// Retention in small transactions, messages arriving meanwhile.
			for _, chunk := range []int{2000, 10000} {
				w := startWriter(db, n+chunk*1000, rate)
				start := time.Now()
				var deleted int64
				var slowest time.Duration
				for {
					s := time.Now()
					res, err := db.Exec("DELETE FROM messages WHERE rowid IN (SELECT rowid FROM messages WHERE timestamp < ? ORDER BY timestamp LIMIT ?)", cutoff, chunk)
					if d := time.Since(s); d > slowest {
						slowest = d
					}
					if err != nil {
						t.Fatal(err)
					}
					k, _ := res.RowsAffected()
					deleted += k
					if k == 0 {
						break
					}
				}
				took := time.Since(start)
				time.Sleep(600 * time.Millisecond)
				worst, failed, written := w.finish()
				report("chunked DELETE by %d: %d rows in %s, slowest chunk %s; writes meanwhile: worst %s, %d lost, %d written",
					chunk, deleted, took.Round(time.Millisecond), slowest.Round(time.Millisecond), worst.Round(time.Millisecond), failed, written)
				cutoff = time.Now().Add(-16 * 24 * time.Hour).UTC().Format("2006-01-02T15:04:05")
			}
			report("file after the deletes, before giving pages back: %.0f MB", fileMB(path))

			// Giving the freed pages back, in steps, messages arriving.
			for _, step := range []int{1000, 5000} {
				var free int64
				db.QueryRow("PRAGMA freelist_count").Scan(&free)
				w := startWriter(db, n+step*10000, rate)
				start := time.Now()
				var slowest time.Duration
				steps := 0
				for {
					db.QueryRow("PRAGMA freelist_count").Scan(&free)
					if free == 0 {
						break
					}
					s := time.Now()
					if _, err := db.Exec("PRAGMA incremental_vacuum(" + strconv.Itoa(step) + ")"); err != nil {
						t.Fatal(err)
					}
					if d := time.Since(s); d > slowest {
						slowest = d
					}
					steps++
				}
				took := time.Since(start)
				db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
				time.Sleep(600 * time.Millisecond)
				worst, failed, written := w.finish()
				report("incremental_vacuum by %d pages: %d steps in %s, slowest %s; writes meanwhile: worst %s, %d lost, %d written; file %.0f MB",
					step, steps, took.Round(time.Millisecond), slowest.Round(time.Millisecond), worst.Round(time.Millisecond), failed, written, fileMB(path))
				// More to free for the next step size.
				db.Exec("DELETE FROM messages WHERE rowid IN (SELECT rowid FROM messages ORDER BY timestamp LIMIT ?)", n/10)
			}

			// What a checkpoint alone costs, the replacement for VACUUM on close.
			start := time.Now()
			db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
			report("wal_checkpoint(TRUNCATE): %s", time.Since(start).Round(time.Millisecond))
		}

		// Startup: the FTS rebuild done at every opening today.
		start := time.Now()
		db.Exec("INSERT INTO messages_fts(messages_fts) VALUES('rebuild')")
		report("FTS rebuild: %s", time.Since(start).Round(time.Millisecond))
		db.Close()
	}

	// Converting an existing database to incremental auto-vacuum: one VACUUM.
	path := filepath.Join(dir, "big-NONE.db")
	db := openBig(t, path, "INCREMENTAL")
	w := startWriter(db, n+90_000_000, rate)
	start := time.Now()
	_, err := db.Exec("VACUUM")
	took := time.Since(start)
	time.Sleep(600 * time.Millisecond)
	worst, failed, written := w.finish()
	report("writes during the conversion: worst %s, %d lost, %d written", worst.Round(time.Millisecond), failed, written)
	_ = took
	var av int
	db.QueryRow("PRAGMA auto_vacuum").Scan(&av)
	report("\nconverting to incremental (VACUUM): %s (err %v), auto_vacuum now %d, file %.0f MB",
		time.Since(start).Round(time.Millisecond), err, av, fileMB(path))
	db.Close()
}

// The store itself on a large database, messages arriving all along:
//
//	SYSLOGSTUDIO_BIGDB_STORE=path/to/existing.db go test -run TestBigStore -v -timeout 60m ./internal/storage
//
// The database is copied first; the copy is what gets cleaned.
func TestBigStore(t *testing.T) {
	src := os.Getenv("SYSLOGSTUDIO_BIGDB_STORE")
	if src == "" {
		t.Skip("set SYSLOGSTUDIO_BIGDB_STORE to an existing database")
	}
	path := filepath.Join(filepath.Dir(src), "store-copy.db")
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"", "-wal", "-shm"} {
		os.Remove(path + s)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	report := func(format string, args ...any) { fmt.Printf(format+"\n", args...) }

	open := func(cfg models.StorageConfig) (*LogStore, time.Duration) {
		cfg.Enabled, cfg.Path = true, path
		start := time.Now()
		ls, err := NewLogStore(cfg, nil)
		if err != nil {
			t.Fatal(err)
		}
		ls.WaitReady()
		return ls, time.Since(start)
	}
	ls, took := open(models.StorageConfig{})
	report("first opening (search index built once): %s", took.Round(time.Millisecond))
	start := time.Now()
	ls.Close()
	report("closing: %s", time.Since(start).Round(time.Millisecond))
	ls, took = open(models.StorageConfig{})
	for _, q := range []struct {
		name string
		opts models.QueryOptions
	}{
		{"newest page", models.QueryOptions{Page: 1, PageSize: 200}},
		{"page 50", models.QueryOptions{Page: 50, PageSize: 200}},
		{"by hostname", models.QueryOptions{Page: 1, PageSize: 200, SortField: "hostname", SortDir: "asc"}},
		{"host filter", models.QueryOptions{Page: 1, PageSize: 200, Filter: models.FilterCriteria{Hostname: "host-1"}}},
		{"search", models.QueryOptions{Page: 1, PageSize: 200, Filter: models.FilterCriteria{Search: "timed out", SearchMode: "text"}}},
	} {
		start := time.Now()
		res := ls.QueryMessages(q.opts)
		report("history %s: %s (%d of %d)", q.name, time.Since(start).Round(time.Millisecond), len(res.Messages), res.Total)
	}
	start = time.Now()
	ls.GetStats()
	report("statistics with a fresh forecast: %s", time.Since(start).Round(time.Millisecond))
	start = time.Now()
	ls.GetStats()
	report("statistics, forecast kept: %s", time.Since(start).Round(time.Millisecond))
	stats := ls.GetStats()
	report("second opening: %s — %d messages, data %.0f MB, file %.0f MB, gives space back: %v",
		took.Round(time.Millisecond), stats.MessageCount, stats.UsedMB, stats.DatabaseSizeMB, stats.SpaceReturns)

	// Messages arriving at 2000 a second, and how many wait in the buffer.
	stop := make(chan struct{})
	var waiting atomic.Int64
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		t := time.NewTicker(10 * time.Millisecond)
		defer t.Stop()
		for i := 50_000_000; ; {
			select {
			case <-stop:
				return
			case <-t.C:
				for k := 0; k < 20; k++ {
					i++
					ls.BufferMessage(bigMessage(i, time.Now()))
				}
			}
		}
	}()
	go func() {
		defer wg.Done()
		t := time.NewTicker(20 * time.Millisecond)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				ls.mu.Lock()
				n := int64(len(ls.buffer))
				ls.mu.Unlock()
				if n > waiting.Load() {
					waiting.Store(n)
				}
			}
		}
	}()
	phase := func(name string, run func()) {
		waiting.Store(0)
		before := ls.GetStats()
		start := time.Now()
		run()
		took := time.Since(start)
		time.Sleep(time.Second)
		after := ls.GetStats()
		main, wal := fileMB(path)-walMB(path), walMB(path)
		report("%s: %s — %d → %d messages, data %.0f → %.0f MB, files %.0f → %.0f MB (database %.0f + log %.0f), most waiting %d (%.1f s of arrivals), lost %d",
			name, took.Round(time.Millisecond), before.MessageCount, after.MessageCount, before.UsedMB, after.UsedMB,
			before.DatabaseSizeMB, after.DatabaseSizeMB, main, wal, waiting.Load(), float64(waiting.Load())/2000, after.DroppedWrites)
	}
	time.Sleep(2 * time.Second)
	phase("idle, for reference", func() { time.Sleep(5 * time.Second) })
	ls.UpdateConfig(models.StorageConfig{Enabled: true, Path: path, RetentionDays: 16})
	phase("cleanup: retention lowered to 16 days, space given back", func() { ls.runCleanup(false) })
	f := ls.GetStats().Forecast
	report("forecast: %.0f messages/day, %.0f B each, %.0f MB/day, steady %.0f MB (%s) in %.1f days, disk %.0f MB free, full in %.1f days",
		f.MessagesPerDay, f.BytesPerMessage, f.GrowthMBPerDay, f.SteadyMB, f.BoundBy, f.SteadyInDays, f.DiskFreeMB, f.DiskFullInDays)
	phase("Compact (VACUUM, writes held in memory)", func() { ls.Compact() })
	close(stop)
	wg.Wait()
	start = time.Now()
	ls.Close()
	report("closing: %s", time.Since(start).Round(time.Millisecond))
}
