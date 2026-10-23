package storage

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

func local(s string) time.Time {
	t, err := time.ParseInLocation("2006-01-02 15:04 Mon", s, time.Local)
	if err != nil {
		panic(err)
	}
	return t
}

func TestSchedule_Runs(t *testing.T) {
	// Thursday 2026-10-22 10:00.
	now := local("2026-10-22 10:00 Thu")
	for _, c := range []struct {
		name       string
		s          models.CleanupSchedule
		prev, next string
	}{
		{"daily, later today", models.CleanupSchedule{Every: models.CleanupDaily, At: "23:30"},
			"2026-10-21 23:30 Wed", "2026-10-22 23:30 Thu"},
		{"daily, earlier today", models.CleanupSchedule{Every: models.CleanupDaily},
			"2026-10-22 03:00 Thu", "2026-10-23 03:00 Fri"},
		{"weekly on Monday", models.CleanupSchedule{Every: models.CleanupWeekly, Weekday: 1, At: "02:00"},
			"2026-10-19 02:00 Mon", "2026-10-26 02:00 Mon"},
		{"weekly on Thursday, later today", models.CleanupSchedule{Every: models.CleanupWeekly, Weekday: 4, At: "12:00"},
			"2026-10-15 12:00 Thu", "2026-10-22 12:00 Thu"},
		{"monthly on the 1st", models.CleanupSchedule{Every: models.CleanupMonthly, MonthDay: 1},
			"2026-10-01 03:00 Thu", "2026-11-01 03:00 Sun"},
		{"monthly on the 31st, a 30-day month next", models.CleanupSchedule{Every: models.CleanupMonthly, MonthDay: 31},
			"2026-09-30 03:00 Wed", "2026-10-31 03:00 Sat"},
	} {
		if got := previousRun(c.s, now); !got.Equal(local(c.prev)) {
			t.Errorf("%s: previous %v, want %s", c.name, got, c.prev)
		}
		if got := nextRun(c.s, now); !got.Equal(local(c.next)) {
			t.Errorf("%s: next %v, want %s", c.name, got, c.next)
		}
	}
	feb := local("2026-02-15 10:00 Sun")
	if got := nextRun(models.CleanupSchedule{Every: models.CleanupMonthly, MonthDay: 31}, feb); !got.Equal(local("2026-02-28 03:00 Sat")) {
		t.Errorf("the 31st in February is %v, want its last day", got)
	}
	if !previousRun(models.CleanupSchedule{}, now).IsZero() || !nextRun(models.CleanupSchedule{}, now).IsZero() {
		t.Error("a continuous cleanup has no schedule")
	}
}

func TestRetentionCutoff_KeepsWholePeriods(t *testing.T) {
	now := local("2026-10-22 10:00 Thu")
	for align, want := range map[string]string{
		models.AlignNone:  "2026-09-22 10:00 Tue",
		models.AlignDay:   "2026-09-22 00:00 Tue",
		models.AlignWeek:  "2026-09-21 00:00 Mon",
		models.AlignMonth: "2026-09-01 00:00 Tue",
	} {
		if got := retentionCutoff(now, 30, align); !got.Equal(local(want)) {
			t.Errorf("30 days aligned to %q: %v, want %s", align, got, want)
		}
	}
}

// A rewrite of the whole database — compaction — no longer costs the
// messages that arrive meanwhile: they wait in the buffer.
func TestLogStore_NothingLostWhileTheDatabaseIsRewritten(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{})
	ls.WaitReady()
	ls.gate.Lock()
	for i := 0; i < 10; i++ {
		ls.BufferMessage(testMessage(i, "h", "a", "during", models.SevError))
	}
	ls.flush() // a tick during the rewrite
	if n := ls.GetStats().MessageCount; n != 0 {
		t.Fatalf("%d messages written during the rewrite", n)
	}
	ls.gate.Unlock()
	ls.flush()
	if n := ls.GetStats().MessageCount; n != 10 {
		t.Fatalf("%d messages written after it, want the 10 that waited", n)
	}
}

func TestLogStore_RequeueKeepsOrderAndCap(t *testing.T) {
	old := maxWriteBuffer
	maxWriteBuffer = 5
	t.Cleanup(func() { maxWriteBuffer = old })
	ls := &LogStore{}
	ls.buffer = []models.SyslogMessage{{ID: "c"}, {ID: "d"}, {ID: "e"}}
	ls.requeue([]models.SyslogMessage{{ID: "x"}, {ID: "a"}, {ID: "b"}})
	var ids []string
	for _, m := range ls.buffer {
		ids = append(ids, m.ID)
	}
	if strings.Join(ids, "") != "abcde" || ls.droppedWrites != 1 {
		t.Fatalf("buffer %v, dropped %d; want abcde and the oldest dropped", ids, ls.droppedWrites)
	}
}

func bulk(t *testing.T, ls *LogStore, n int, from time.Time, step time.Duration) {
	t.Helper()
	text := strings.Repeat("payload ", 40)
	var msgs []models.SyslogMessage
	for i := 0; i < n; i++ {
		m := testMessage(i, "host", "app", text+fmt.Sprint(i), models.SevInformational)
		m.ID = fmt.Sprintf("bulk-%d-%d", from.Unix(), i)
		m.Timestamp = from.Add(time.Duration(i) * step)
		msgs = append(msgs, m)
	}
	if err := ls.InsertMessages(msgs); err != nil {
		t.Fatal(err)
	}
}

// A new database gives the space of deleted messages back to the disk by
// itself: the file shrinks after a cleanup, with no VACUUM.
func TestLogStore_SpaceGoesBackAfterACleanup(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{RetentionDays: 1})
	ls.WaitReady()
	if !spaceReturns(ls.handle()) {
		t.Fatal("a new database does not give space back")
	}
	bulk(t, ls, 4000, time.Now().Add(-72*time.Hour), time.Second) // all too old
	bulk(t, ls, 500, time.Now().Add(-time.Hour), time.Second)
	ls.handle().Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	before := ls.fileBytes()
	ls.runCleanup(false)
	after := ls.fileBytes()
	if n := ls.GetStats().MessageCount; n != 500 {
		t.Fatalf("%d messages left, want 500", n)
	}
	if after >= before*2/3 {
		t.Fatalf("file %d bytes after the cleanup, %d before: the space did not come back", after, before)
	}
	r := lastCleanup(ls.handle())
	if r == nil || r.Deleted != 4000 || r.FreedMB <= 0 {
		t.Fatalf("last cleanup recorded as %+v", r)
	}
}

// A database from before is switched to giving space back, once.
func TestLogStore_OlderDatabaseIsConverted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "logs.db")
	raw, err := sql.Open("sqlite", path+"?_pragma=journal_mode(wal)")
	if err != nil {
		t.Fatal(err)
	}
	if err := initSchema(raw); err != nil {
		t.Fatal(err)
	}
	raw.Close()

	ls := newTestStore(t, models.StorageConfig{Path: path})
	ls.WaitReady()
	db := ls.handle()
	if spaceReturns(db) {
		t.Fatal("the older database already gives space back")
	}
	ls.convertForSpaceReturn(db)
	if !spaceReturns(db) {
		t.Fatal("not converted")
	}
	// Not with the space left to the Compact button.
	manual := newTestStore(t, models.StorageConfig{Path: filepath.Join(t.TempDir(), "m.db"), Compaction: models.CompactManual})
	manual.WaitReady()
	manual.handle().Exec("PRAGMA auto_vacuum = NONE")
	manual.handle().Exec("VACUUM")
	manual.convertForSpaceReturn(manual.handle())
	if spaceReturns(manual.handle()) {
		t.Error("converted although compaction is manual")
	}
}

// Scheduled, the age limit waits for its run; the size and count limits do
// not wait for anything.
func TestLogStore_ScheduledCleanup(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{
		RetentionDays: 1, MaxMessages: 300,
		Cleanup: models.CleanupSchedule{Every: models.CleanupWeekly, Weekday: 1},
	})
	ls.WaitReady()
	bulk(t, ls, 200, time.Now().Add(-72*time.Hour), time.Second) // too old
	bulk(t, ls, 200, time.Now().Add(-time.Hour), time.Second)
	ls.runCleanup(false)
	if n := ls.GetStats().MessageCount; n != 300 {
		t.Fatalf("%d messages between runs, want the 300 the count limit keeps", n)
	}
	ls.runCleanup(true)
	if n := ls.GetStats().MessageCount; n != 200 {
		t.Fatalf("%d messages after the run, want the 200 recent ones", n)
	}
	stats := ls.GetStats()
	if next, err := time.Parse(time.RFC3339, stats.NextCleanup); err != nil || next.Weekday() != time.Monday {
		t.Errorf("next cleanup %q, want a Monday", stats.NextCleanup)
	}
	if getMeta(ls.handle(), metaLastScheduled) == "" {
		t.Error("the run was not recorded, so it would run again")
	}
}

func TestLogStore_Forecast(t *testing.T) {
	ls := newTestStore(t, models.StorageConfig{RetentionDays: 10})
	ls.WaitReady()
	// 2880 messages over the last 24 hours: 2 a minute.
	bulk(t, ls, 2880, time.Now().Add(-24*time.Hour+time.Minute), 30*time.Second)
	f := ls.GetStats().Forecast
	if f.MessagesPerDay < 2700 || f.MessagesPerDay > 3000 {
		t.Errorf("%.0f messages a day, want about 2880", f.MessagesPerDay)
	}
	if f.BoundBy != "age" || f.SteadyMB <= 0 || f.SteadyInDays <= 0 {
		t.Errorf("forecast %+v, want the age limit holding it", f)
	}
	if want := f.GrowthMBPerDay * 10; f.SteadyMB < want*0.99 || f.SteadyMB > want*1.01 {
		t.Errorf("steady %.2f MB, want ten days of %.3f MB", f.SteadyMB, f.GrowthMBPerDay)
	}
	if f.DiskFreeMB <= 0 {
		t.Error("free disk space unknown")
	}
	if f.DiskFullInDays != 0 {
		t.Errorf("a bounded database of a few MB fills the disk in %.0f days", f.DiskFullInDays)
	}

	unbounded := forecast(ls.handle(), models.StorageConfig{}, time.Now(), 2880, 2880*600, 2880*600, t.TempDir())
	if unbounded.BoundBy != "" || unbounded.DiskFullInDays <= 0 {
		t.Errorf("without limits the disk should fill some day: %+v", unbounded)
	}
}
