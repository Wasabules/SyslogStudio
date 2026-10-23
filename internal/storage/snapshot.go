package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"SyslogStudio/internal/models"
)

// Copies of the database: taken while messages keep arriving, opened to be
// read, or put in place of the database.

// ErrNotOpen is a database that is locked, or turned off.
var ErrNotOpen = errors.New("the database is not open")

// Snapshot writes a copy of the database to path as it stands when the copy
// starts: VACUUM INTO reads it in one transaction while the flushes go on
// writing beside it. The write gate is held shared, so that a compaction
// waits for the copy instead of failing on the lock it needs.
func (ls *LogStore) Snapshot(ctx context.Context, path string) error {
	db := ls.handle()
	if db == nil || ls.readOnly {
		return ErrNotOpen
	}
	ls.gate.RLock()
	defer ls.gate.RUnlock()
	_, err := db.ExecContext(ctx, "VACUUM INTO ?", path)
	return err
}

// UsedBytes is what the rows and their index take: about what a copy weighs.
func (ls *LogStore) UsedBytes() int64 {
	db := ls.handle()
	if db == nil {
		return 0
	}
	return ls.usedBytes(db)
}

// OpenSnapshot opens a copy of the database to be read, and only read: no
// write buffer, no cleanup, no index to build.
//
// It checks that the file is a SyslogStudio database, not that every page of
// it is sound: a backup is authenticated chunk by chunk as it is decrypted,
// and reading every page of a million messages takes ten seconds.
// CheckSnapshot does, before a copy is put in place of the database.
func OpenSnapshot(path string) (*LogStore, error) {
	db, err := openReadOnly(path)
	if err != nil {
		return nil, err
	}
	ready := make(chan struct{})
	close(ready)
	return &LogStore{
		db: db, config: models.StorageConfig{Enabled: true, Path: path},
		ftsReady: true, ftsReadyCh: ready, readOnly: true,
	}, nil
}

func openReadOnly(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path+
		"?_pragma=query_only(1)"+
		"&_pragma=busy_timeout(5000)"+
		"&_pragma=cache_size(-64000)"+
		"&_pragma=mmap_size(0)"+
		"&_pragma=temp_store(memory)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	var n int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'messages'").Scan(&n); err != nil {
		db.Close()
		return nil, fmt.Errorf("not a database: %w", err)
	}
	if n == 0 {
		db.Close()
		return nil, errors.New("not a SyslogStudio database")
	}
	return db, nil
}

// CheckSnapshot says whether the file at path is a SyslogStudio database
// whose every page reads.
func CheckSnapshot(path string) error {
	db, err := openReadOnly(path)
	if err != nil {
		return err
	}
	defer db.Close()
	var check string
	if err := db.QueryRow("PRAGMA quick_check").Scan(&check); err != nil {
		return fmt.Errorf("the database does not read: %w", err)
	}
	if check != "ok" {
		return fmt.Errorf("the database is damaged: %s", check)
	}
	return nil
}

// Span is how many messages the database holds, and from when to when.
func (ls *LogStore) Span() (count int64, oldest, newest string) {
	db := ls.handle()
	if db == nil {
		return 0, "", ""
	}
	var lo, hi sql.NullString
	db.QueryRow("SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM messages").Scan(&count, &lo, &hi)
	return count, lo.String, hi.String
}

// Mark is where the database stands now: the messages written after it are
// those Replace carries over.
func (ls *LogStore) Mark() int64 {
	db := ls.handle()
	if db == nil {
		return 0
	}
	var mark int64
	db.QueryRow("SELECT COALESCE(MAX(rowid), 0) FROM messages").Scan(&mark)
	return mark
}

// Replace puts the database at path in place of this one, which it moves
// into; path should have passed CheckSnapshot. The messages written to this
// one after since (Mark) go to the new one, and so do those that arrive
// meanwhile, which wait in the write buffer: what was received while a
// restore was being prepared is not lost with the database it replaces.
//
// Writes stop only for the swap itself. What was written after since is read
// before, all but the last moment's; and it goes into the new database once
// writes have resumed, in short transactions between theirs.
func (ls *LogStore) Replace(path string, since int64) error {
	db := ls.handle()
	if db == nil || ls.readOnly {
		return ErrNotOpen
	}
	check, err := openReadOnly(path)
	if err != nil {
		return err
	}
	check.Close()
	dbPath, err := ResolveDBPath(ls.currentConfig().Path)
	if err != nil {
		return err
	}
	start := time.Now()
	ls.WaitReady()
	upTo := ls.Mark()
	carried, err := ls.messagesBetween(db, since, upTo)
	if err != nil {
		return fmt.Errorf("read the messages received meanwhile, so nothing was replaced: %w", err)
	}

	// Stop the loops, keeping what waits in the buffer for the new database.
	ls.mu.Lock()
	ls.holdBuffer = true
	ls.mu.Unlock()
	close(ls.stopCh)
	ls.wg.Wait()
	held := time.Now()

	last, err := ls.messagesBetween(db, upTo, -1)
	if err != nil {
		ls.restart(db)
		return fmt.Errorf("read the messages received meanwhile, so nothing was replaced: %w", err)
	}
	carried = append(carried, last...)
	db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	db.Close()

	os.Remove(dbPath + "-wal")
	os.Remove(dbPath + "-shm")
	replaceErr := os.Rename(path, dbPath)
	if replaceErr != nil {
		slog.Warn("log store: the database could not be replaced, keeping it", "error", replaceErr)
	}
	// The new database, or the one that was there if it could not be moved.
	next, err := sql.Open("sqlite", dsn(dbPath))
	if err == nil {
		next.SetMaxOpenConns(4)
		err = initSchema(next)
	}
	if err != nil {
		return fmt.Errorf("reopen the database: %w", err)
	}
	ls.restart(next)
	heldFor := time.Since(held)

	if replaceErr == nil {
		for i := 0; i < len(carried); i += writeChunk {
			if err := ls.InsertMessages(carried[i:min(i+writeChunk, len(carried))]); err != nil {
				// To the buffer, for the flushes to write.
				ls.requeue(carried[i:])
				break
			}
		}
	}
	slog.Info("log store: database replaced", "carried", len(carried),
		"writesHeld", heldFor.Round(time.Millisecond), "took", time.Since(start).Round(time.Millisecond), "error", replaceErr)
	return replaceErr
}

// messagesBetween reads the messages written after the rowid from, up to the
// rowid to included; -1 is no upper bound.
func (ls *LogStore) messagesBetween(db *sql.DB, from, to int64) ([]models.SyslogMessage, error) {
	if to < 0 {
		to = 1<<63 - 1
	}
	rows, err := db.Query("SELECT id, timestamp, received_at, severity, severity_label, facility, facility_label, hostname, app_name, proc_id, msg_id, message, raw_message, source_ip, protocol, version, structured_data FROM messages WHERE rowid > ? AND rowid <= ? ORDER BY rowid", from, to)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var msgs []models.SyslogMessage
	for rows.Next() {
		if msg := ls.scanMessage(rows); msg != nil {
			msgs = append(msgs, *msg)
		}
	}
	return msgs, rows.Err()
}

// restart runs the store on db again: the loops Replace stopped.
func (ls *LogStore) restart(db *sql.DB) {
	ls.mu.Lock()
	ls.db = db
	ls.stopCh = make(chan struct{})
	ls.ftsReadyCh = make(chan struct{})
	ls.ftsReady = false
	ls.converted = false
	ls.forecastAt = time.Time{}
	ls.holdBuffer = false
	ls.mu.Unlock()

	go ls.rebuildFTS()
	ls.wg.Add(2)
	go ls.flushLoop()
	go ls.cleanupLoop()
}

func (ls *LogStore) holding() bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.holdBuffer
}
