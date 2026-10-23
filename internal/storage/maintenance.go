package storage

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"math"
	"path/filepath"
	"strconv"
	"time"

	"SyslogStudio/internal/models"
)

// Retention and compaction, done so that messages keep arriving meanwhile:
//
//   - old messages go in small transactions (deleteChunk rows), each over in
//     milliseconds, so the writes of incoming messages pass between them;
//   - the database is in SQLite's incremental auto-vacuum mode, which hands
//     the pages of deleted rows back to the disk a step at a time
//     (giveBackStep pages) — the file shrinks as it goes, with no VACUUM;
//   - what does need the whole file — converting an older database to that
//     mode, a full compaction — holds the write gate, and the incoming
//     messages wait in the write buffer meanwhile instead of being lost.
//
// The sizes come from internal/storage/bigdb_test.go on a database of a
// million messages.

const (
	// deleteChunk is how many messages one retention transaction deletes. A
	// million-message database measured 2.9 s of held-up writes at 2000 per
	// chunk and 3.3 s at 10000, against 11 s for one DELETE; the larger chunk
	// finished in half the time.
	deleteChunk = 5000
	// giveBackStep is how many pages (4 KiB each) one step returns to the disk.
	giveBackStep = 1000
	// maintenancePause lets the writes in between two steps.
	maintenancePause = 5 * time.Millisecond
	// defaultCleanupAt is when a scheduled cleanup runs if no time is given.
	defaultCleanupAt = "03:00"
)

// --- when ---------------------------------------------------------------

func clock(at string) (h, m int) {
	if at == "" {
		at = defaultCleanupAt
	}
	t, err := time.Parse("15:04", at)
	if err != nil {
		t, _ = time.Parse("15:04", defaultCleanupAt)
	}
	return t.Hour(), t.Minute()
}

func daysIn(year int, month time.Month, loc *time.Location) int {
	return time.Date(year, month+1, 0, 0, 0, 0, 0, loc).Day()
}

// occurrence is the scheduled time in the period containing day.
func occurrence(s models.CleanupSchedule, day time.Time) time.Time {
	h, m := clock(s.At)
	y, mo, d := day.Date()
	loc := day.Location()
	switch s.Every {
	case models.CleanupWeekly:
		d -= (int(day.Weekday()) - s.Weekday + 7) % 7
	case models.CleanupMonthly:
		d = s.MonthDay
		if d < 1 {
			d = 1
		}
		if n := daysIn(y, mo, loc); d > n {
			d = n
		}
	}
	return time.Date(y, mo, d, h, m, 0, 0, loc)
}

// previousRun is the last scheduled time at or before now; zero for a
// continuous cleanup.
func previousRun(s models.CleanupSchedule, now time.Time) time.Time {
	if s.Every == models.CleanupContinuous {
		return time.Time{}
	}
	if t := occurrence(s, now); !t.After(now) {
		return t
	}
	switch s.Every {
	case models.CleanupDaily:
		return occurrence(s, now.AddDate(0, 0, -1))
	case models.CleanupWeekly:
		return occurrence(s, now.AddDate(0, 0, -7))
	default:
		y, mo, _ := now.Date()
		return occurrence(s, time.Date(y, mo-1, 1, 12, 0, 0, 0, now.Location()))
	}
}

// nextRun is the first scheduled time after now; zero for a continuous
// cleanup.
func nextRun(s models.CleanupSchedule, now time.Time) time.Time {
	if s.Every == models.CleanupContinuous {
		return time.Time{}
	}
	t := occurrence(s, now)
	if t.After(now) {
		return t
	}
	switch s.Every {
	case models.CleanupDaily:
		return occurrence(s, now.AddDate(0, 0, 1))
	case models.CleanupWeekly:
		return occurrence(s, now.AddDate(0, 0, 7))
	default:
		y, mo, _ := now.Date()
		return occurrence(s, time.Date(y, mo+1, 1, 12, 0, 0, 0, now.Location()))
	}
}

// retentionCutoff is the time before which messages go: the retention back
// from now, moved back to the start of its day, week or month when whole
// periods are kept.
func retentionCutoff(now time.Time, days int, align string) time.Time {
	c := now.AddDate(0, 0, -days)
	y, mo, d := c.Date()
	loc := c.Location()
	switch align {
	case models.AlignDay:
		return time.Date(y, mo, d, 0, 0, 0, 0, loc)
	case models.AlignWeek:
		back := (int(c.Weekday()) + 6) % 7 // days since Monday
		return time.Date(y, mo, d-back, 0, 0, 0, 0, loc)
	case models.AlignMonth:
		return time.Date(y, mo, 1, 0, 0, 0, 0, loc)
	}
	return c
}

// --- how ------------------------------------------------------------------

// deleteInChunks deletes the messages a condition picks, oldest first,
// deleteChunk at a time, at most limit of them (0: all), and says how many
// went. Each chunk is its own transaction, over before an incoming write has
// to wait long.
func (ls *LogStore) deleteInChunks(db *sql.DB, where string, limit int64, args ...any) (int64, error) {
	var total int64
	for limit == 0 || total < limit {
		n := int64(deleteChunk)
		if limit > 0 && limit-total < n {
			n = limit - total
		}
		res, err := db.Exec("DELETE FROM messages WHERE rowid IN (SELECT rowid FROM messages"+where+
			" ORDER BY timestamp LIMIT ?)", append(append([]any{}, args...), n)...)
		if err != nil {
			return total, err
		}
		k, _ := res.RowsAffected()
		total += k
		if k < n || ls.stopping() {
			break
		}
		time.Sleep(maintenancePause)
	}
	return total, nil
}

func (ls *LogStore) stopping() bool {
	select {
	case <-ls.stopCh:
		return true
	default:
		return false
	}
}

func pragmaInt(db *sql.DB, name string) int64 {
	var v int64
	db.QueryRow("PRAGMA " + name).Scan(&v)
	return v
}

// spaceReturns reports whether the database gives its free pages back to the
// disk by itself: incremental auto-vacuum.
func spaceReturns(db *sql.DB) bool { return pragmaInt(db, "auto_vacuum") == 2 }

// giveBack returns the pages deleted rows left free to the disk, a step at a
// time, and says how many bytes went.
func (ls *LogStore) giveBack(db *sql.DB) int64 {
	if !spaceReturns(db) {
		return 0
	}
	size := pragmaInt(db, "page_size")
	var freed int64
	for !ls.stopping() {
		free := pragmaInt(db, "freelist_count")
		if free == 0 {
			break
		}
		if _, err := db.Exec("PRAGMA incremental_vacuum(" + strconv.Itoa(giveBackStep) + ")"); err != nil {
			slog.Warn("log store: giving space back failed", "error", err)
			break
		}
		freed += (free - pragmaInt(db, "freelist_count")) * size
		time.Sleep(maintenancePause)
	}
	// The returned pages leave the file at the next checkpoint; the write-
	// ahead log shrinks with a truncating one.
	db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	return freed
}

// rewrite runs a statement that needs the whole database — VACUUM — with the
// write gate held: incoming messages wait in the write buffer meanwhile, and
// are written once it is over.
func (ls *LogStore) rewrite(db *sql.DB, stmt string) error {
	ls.gate.Lock()
	ls.setCompacting(true)
	defer func() {
		ls.setCompacting(false)
		ls.gate.Unlock()
	}()
	start := time.Now()
	_, err := db.Exec(stmt)
	// The rewritten database is all in the write-ahead log until a
	// checkpoint; with no write in the way yet, this one completes.
	db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	slog.Info("log store: database rewritten", "statement", stmt, "took", time.Since(start).Round(time.Millisecond), "error", err)
	return err
}

func (ls *LogStore) setCompacting(on bool) {
	ls.mu.Lock()
	ls.compacting = on
	ls.mu.Unlock()
}

// convertForSpaceReturn puts a database made before incremental auto-vacuum
// into that mode, which takes one VACUUM. Done once, in the background, when
// space is to go back automatically.
func (ls *LogStore) convertForSpaceReturn(db *sql.DB) {
	if ls.currentConfig().Compaction != models.CompactAuto || spaceReturns(db) {
		return
	}
	ls.mu.Lock()
	tried := ls.converted
	ls.converted = true
	ls.mu.Unlock()
	if tried {
		return
	}
	// The connection's auto_vacuum pragma (see dsn) makes the VACUUM switch.
	if err := ls.rewrite(db, "VACUUM"); err != nil {
		slog.Warn("log store: could not switch to giving space back", "error", err)
	}
}

func (ls *LogStore) currentConfig() models.StorageConfig {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.config
}

// --- what the last one did ---------------------------------------------------

func setMeta(db *sql.DB, key, value string) {
	db.Exec("INSERT INTO meta(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
}

func getMeta(db *sql.DB, key string) string {
	var v string
	db.QueryRow("SELECT value FROM meta WHERE key = ?", key).Scan(&v)
	return v
}

const (
	metaLastCleanup   = "last_cleanup"
	metaLastScheduled = "last_scheduled_cleanup"
	metaFTSBuilt      = "fts_built"
)

func lastCleanup(db *sql.DB) *models.CleanupRecord {
	var r models.CleanupRecord
	if json.Unmarshal([]byte(getMeta(db, metaLastCleanup)), &r) != nil {
		return nil
	}
	return &r
}

// --- where it is heading --------------------------------------------------------

// forecast is where the database is heading at the rate messages arrive.
func forecast(db *sql.DB, cfg models.StorageConfig, now time.Time, count, used, file int64, dir string) models.StorageForecast {
	var f models.StorageForecast
	const mb = 1 << 20

	// The rate: over the last week if the history goes back that far, else
	// over the last day, scaled from the part of it the history covers.
	var oldest sql.NullString
	db.QueryRow("SELECT MIN(timestamp) FROM messages").Scan(&oldest)
	window := 7 * 24 * time.Hour
	if t, err := time.Parse(time.RFC3339Nano, oldest.String); oldest.Valid && err == nil && now.Sub(t) < window {
		window = 24 * time.Hour
		if span := now.Sub(t); span < window {
			window = max(span, time.Hour)
		}
	}
	var recent int64
	db.QueryRow("SELECT COUNT(*) FROM messages WHERE timestamp >= ?", sqlTime(now.Add(-window))).Scan(&recent)
	f.MessagesPerDay = float64(recent) / window.Hours() * 24

	f.BytesPerMessage = 560 // until there is enough to measure
	if count >= 1000 {
		f.BytesPerMessage = float64(used) / float64(count)
	}
	f.GrowthMBPerDay = f.MessagesPerDay * f.BytesPerMessage / mb

	// Where the retention and the limits hold it: the tightest of them. A
	// scheduled cleanup lets a whole period through before it runs, and whole
	// periods kept add up to one more.
	bound := func(m float64, by string) {
		if m > 0 && (f.BoundBy == "" || m < f.SteadyMB) {
			f.SteadyMB, f.BoundBy = m, by
		}
	}
	if cfg.RetentionDays > 0 && f.GrowthMBPerDay > 0 {
		days := float64(cfg.RetentionDays) + slackDays(cfg.Cleanup.Every) + slackDays(cfg.RetentionAlign)
		bound(f.GrowthMBPerDay*days, "age")
	}
	if cfg.MaxMessages > 0 {
		bound(float64(cfg.MaxMessages)*f.BytesPerMessage/mb, "count")
	}
	if cfg.MaxSizeMB > 0 {
		bound(float64(cfg.MaxSizeMB), "size")
	}
	usedMB, fileMB := float64(used)/mb, float64(file)/mb
	if f.BoundBy != "" && f.GrowthMBPerDay > 0 && f.SteadyMB > usedMB {
		f.SteadyInDays = (f.SteadyMB - usedMB) / f.GrowthMBPerDay
	}

	// The file follows the data when space goes back; otherwise it keeps the
	// highest size the data reached.
	f.FileMB = f.SteadyMB
	if cfg.Compaction == models.CompactManual {
		f.FileMB = math.Max(f.SteadyMB, fileMB)
	}

	if free, ok := diskFree(dir); ok {
		f.DiskFreeMB = float64(free) / mb
		// What the database will still take from the disk.
		more := math.Inf(1)
		if f.BoundBy != "" {
			more = f.FileMB - fileMB
		}
		if f.GrowthMBPerDay > 0 && more > f.DiskFreeMB {
			f.DiskFullInDays = f.DiskFreeMB / f.GrowthMBPerDay
		}
	}
	return f
}

// slackDays is how much more than the retention a schedule or an alignment
// can keep: the longest wait for the next run, the longest partial period.
func slackDays(period string) float64 {
	switch period {
	case models.CleanupDaily, models.AlignDay:
		return 1
	case models.CleanupWeekly, models.AlignWeek:
		return 7
	case models.CleanupMonthly, models.AlignMonth:
		return 31
	}
	return 0
}

func dbDir(path string) string {
	if p, err := ResolveDBPath(path); err == nil {
		return filepath.Dir(p)
	}
	return ""
}

// formatRFC3339 is time.Time as the window reads it, "" for the zero time.
func formatRFC3339(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}
