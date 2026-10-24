package storage

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/search"
	"SyslogStudio/internal/vault"

	_ "modernc.org/sqlite"
)

const (
	logStoreFlushInterval = 500 * time.Millisecond
	// cleanupEvery is how often the retention limits are applied; cleanupTick,
	// how often a scheduled cleanup is checked for.
	cleanupEvery = 5 * time.Minute
	cleanupTick  = time.Minute
	// forecastFor is how long a forecast is kept.
	forecastFor = time.Minute
	dbFileName  = "logs.db"
)

// maxWriteBuffer caps the in-memory pending-write buffer so a message flood
// that outruns SQLite commits (slow disk, VACUUM, retention delete) bounds
// memory instead of growing without limit until OOM.
//
// A variable rather than a constant so tests can lower it: exercising the
// overflow path at the production value means actually buffering 200k messages
// and letting the flush loop write them, which takes minutes under -race for a
// branch that is three lines long.
var maxWriteBuffer = 200000

// writeChunk is how many messages one write transaction holds: about a second
// on a database of a million messages, well inside the time another writer
// waits for the lock (busy_timeout). Writing a backlog of tens of thousands
// in one transaction kept the others out past it.
const writeChunk = 2000

// LogStore handles SQLite-based message persistence.
type LogStore struct {
	mu            sync.Mutex
	db            *sql.DB
	config        models.StorageConfig
	buffer        []models.SyslogMessage
	droppedWrites int64
	emitter       event.EventEmitter

	stopCh chan struct{}
	wg     sync.WaitGroup

	ftsReady   bool          // true when FTS index rebuild is complete
	ftsReadyCh chan struct{} // closed when FTS rebuild completes

	locked             bool   // true if encrypted db exists but not yet unlocked
	encryptionPassword string // in-memory only, set when unlocked or encryption enabled

	// gate lets the flush write while nothing rewrites the whole database:
	// flushes hold it shared, a VACUUM or an index rebuild exclusively — and
	// incoming messages wait in the buffer meanwhile (see rewrite).
	gate       sync.RWMutex
	compacting bool
	// converted is set once the switch to giving space back has been tried,
	// so that a failure — a full disk — is not retried every minute.
	converted bool
	// forecast is the last forecast, kept a minute: the status bar asks for
	// the statistics every few seconds, and the forecast reads the index.
	forecast   models.StorageForecast
	forecastAt time.Time
	// readOnly is a copy opened to be read (OpenSnapshot); holdBuffer keeps
	// the buffer from being written while the database is replaced.
	readOnly   bool
	holdBuffer bool
}

// NewLogStore creates and initializes a LogStore.
// If an encrypted database exists, the store is returned in locked mode (db == nil).
func NewLogStore(config models.StorageConfig, emitter event.EventEmitter) (*LogStore, error) {
	if !config.Enabled {
		return &LogStore{config: config}, nil
	}

	dbPath, err := ResolveDBPath(config.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DB path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create DB directory: %w", err)
	}

	// If encrypted file exists, return a locked store awaiting password
	if EncryptedFileExists(dbPath) {
		slog.Info("encrypted database found, awaiting unlock", "path", dbPath+".enc")
		return &LogStore{config: config, emitter: emitter, locked: true}, nil
	}

	return openDatabase(dbPath, config, emitter)
}

// dsn is how every connection to the database is opened. auto_vacuum is set on
// each of them because it only takes on a connection that creates the first
// table, or runs a VACUUM: a new database gives freed space back from the
// start, an older one once convertForSpaceReturn has rewritten it.
func dsn(dbPath string) string {
	return dbPath +
		"?_pragma=journal_mode(wal)" +
		"&_pragma=synchronous(normal)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=cache_size(-64000)" + // 64 MB cache
		// No memory mapping: on Windows a file another connection of the
		// pool has mapped cannot be truncated, so the space cleanups give
		// back never left the file while the store was in use — and the
		// cleanup itself took twice as long. Measured on a million messages.
		"&_pragma=mmap_size(0)" +
		"&_pragma=temp_store(memory)" +
		"&_pragma=auto_vacuum(incremental)" +
		// After a large cleanup or a compaction the write-ahead log has grown
		// by as much as was rewritten; once checkpointed, it is cut back to
		// this rather than kept at its largest.
		"&_pragma=journal_size_limit(67108864)"
}

// openDatabase opens the SQLite database and starts background goroutines.
func openDatabase(dbPath string, config models.StorageConfig, emitter event.EventEmitter) (*LogStore, error) {
	db, err := sql.Open("sqlite", dsn(dbPath))
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db.SetMaxOpenConns(4)

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to init schema: %w", err)
	}

	ls := &LogStore{
		db:         db,
		config:     config,
		buffer:     make([]models.SyslogMessage, 0, 256),
		emitter:    emitter,
		stopCh:     make(chan struct{}),
		ftsReadyCh: make(chan struct{}),
	}

	// FTS rebuild in background — app becomes usable immediately
	go ls.rebuildFTS()

	ls.wg.Add(2)
	go ls.flushLoop()
	go ls.cleanupLoop()

	slog.Info("log store initialized", "path", dbPath)
	return ls, nil
}

// UnlockAndOpen decrypts the database with the given password and opens it.
func (ls *LogStore) UnlockAndOpen(password string) error {
	dbPath, err := ResolveDBPath(ls.config.Path)
	if err != nil {
		return fmt.Errorf("resolve path: %w", err)
	}

	encPath := dbPath + ".enc"

	// Decrypt with progress rescaled to 0-70% of total unlock
	scaledProgress := func(p CryptoProgress) {
		p.Percent = p.Percent * 0.70
		ls.emitCryptoProgress(p)
	}
	// The current format is decrypted a chunk at a time; a file written
	// before it, whole, as it always was.
	if vault.IsVaultFile(encPath) {
		size := fileSize(encPath)
		_, err := vault.DecryptFile(encPath, dbPath, password, func(done int64) {
			scaledProgress(CryptoProgress{Phase: "decrypting", Percent: percentOf(done, size), SizeMB: float64(size) / (1 << 20)})
		})
		if err != nil {
			return err
		}
	} else if err := DecryptFileWithProgress(encPath, dbPath, password, scaledProgress); err != nil {
		return err
	}

	// Decryption succeeded — remove encrypted file
	os.Remove(encPath)

	// Phase: opening database (70-75%)
	ls.emitCryptoProgress(CryptoProgress{Phase: "initializing", Percent: 72})

	db, err := sql.Open("sqlite", dsn(dbPath))
	if err != nil {
		return fmt.Errorf("open database after decrypt: %w", err)
	}
	db.SetMaxOpenConns(4)

	// Phase: initializing schema (75-90%)
	ls.emitCryptoProgress(CryptoProgress{Phase: "initializing", Percent: 80})

	if err := initSchema(db); err != nil {
		db.Close()
		return fmt.Errorf("init schema after decrypt: %w", err)
	}

	ls.emitCryptoProgress(CryptoProgress{Phase: "done", Percent: 100})

	ls.mu.Lock()
	ls.db = db
	ls.buffer = make([]models.SyslogMessage, 0, 256)
	ls.stopCh = make(chan struct{})
	ls.locked = false
	ls.encryptionPassword = password
	ls.ftsReadyCh = make(chan struct{})
	ls.mu.Unlock()

	// FTS rebuild in background — app becomes usable immediately
	go ls.rebuildFTS()

	ls.wg.Add(2)
	go ls.flushLoop()
	go ls.cleanupLoop()

	slog.Info("database unlocked and opened", "path", dbPath)
	return nil
}

// emitCryptoProgress sends encrypt/decrypt progress to the frontend.
func (ls *LogStore) emitCryptoProgress(p CryptoProgress) {
	if ls.emitter != nil {
		ls.emitter.Emit("syslog:cryptoProgress", p)
	}
}

// handle returns the current database handle, read under the lock. It may be
// nil when persistence is disabled or the database is still locked. Callers
// take the handle once and use that local for the whole operation instead of
// touching ls.db repeatedly: Close() clears the field, so an unsynchronized
// read races with it and a nil-check followed by a later read can still hit a
// nil pointer. A *sql.DB stays safe to call after Close — its methods return
// sql.ErrConnDone rather than panicking.
func (ls *LogStore) handle() *sql.DB {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.db
}

// IsReady returns true if the database is fully initialized (FTS index built).
func (ls *LogStore) IsReady() bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.ftsReady
}

// IsLocked returns true if the database is encrypted and not yet unlocked.
func (ls *LogStore) IsLocked() bool {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.locked
}

// SetEncryptionPassword sets the in-memory password for encrypting on Close.
func (ls *LogStore) SetEncryptionPassword(password string) {
	ls.mu.Lock()
	ls.encryptionPassword = password
	ls.mu.Unlock()
}

// DBPathIn is where the database lives inside a data directory, when the
// configuration does not name a path of its own.
func DBPathIn(dir string) string {
	return filepath.Join(dir, dbFileName)
}

// ResolveDBPath returns the database file path, using the default location if configPath is empty.
func ResolveDBPath(configPath string) (string, error) {
	if configPath != "" {
		return configPath, nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "SyslogStudio", dbFileName), nil
}

func initSchema(db *sql.DB) error {
	schema := `
	CREATE TABLE IF NOT EXISTS messages (
		id              TEXT PRIMARY KEY,
		timestamp       DATETIME NOT NULL,
		received_at     DATETIME NOT NULL,
		severity        INTEGER NOT NULL,
		severity_label  TEXT NOT NULL,
		facility        INTEGER NOT NULL,
		facility_label  TEXT NOT NULL,
		hostname        TEXT DEFAULT '',
		app_name        TEXT DEFAULT '',
		proc_id         TEXT DEFAULT '',
		msg_id          TEXT DEFAULT '',
		message         TEXT DEFAULT '',
		raw_message     TEXT DEFAULT '',
		source_ip       TEXT DEFAULT '',
		protocol        TEXT DEFAULT '',
		version         INTEGER DEFAULT 0,
		structured_data TEXT DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_timestamp ON messages(timestamp);
	CREATE INDEX IF NOT EXISTS idx_severity ON messages(severity);
	CREATE INDEX IF NOT EXISTS idx_hostname_nocase ON messages(hostname COLLATE NOCASE);
	CREATE INDEX IF NOT EXISTS idx_app_name_nocase ON messages(app_name COLLATE NOCASE);
	CREATE INDEX IF NOT EXISTS idx_source_ip_nocase ON messages(source_ip COLLATE NOCASE);

	-- What the store remembers about itself: the last cleanup, whether the
	-- search index has been built.
	CREATE TABLE IF NOT EXISTS meta (
		key   TEXT PRIMARY KEY,
		value TEXT NOT NULL
	);

	CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
		message, raw_message,
		content='messages',
		content_rowid='rowid'
	);

	-- Triggers to keep FTS index in sync with main table
	CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
		INSERT INTO messages_fts(rowid, message, raw_message)
		VALUES (new.rowid, new.message, new.raw_message);
	END;
	CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
		INSERT INTO messages_fts(messages_fts, rowid, message, raw_message)
		VALUES ('delete', old.rowid, old.message, old.raw_message);
	END;
	`
	_, err := db.Exec(schema)
	return err
}

// rebuildFTS rebuilds the FTS5 index in the background.
// Signals completion by setting ftsReady and closing ftsReadyCh.
func (ls *LogStore) rebuildFTS() {
	defer func() {
		ls.mu.Lock()
		ls.ftsReady = true
		ls.mu.Unlock()
		if ls.ftsReadyCh != nil {
			close(ls.ftsReadyCh)
		}
		if ls.emitter != nil {
			ls.emitter.Emit("syslog:storageReady")
		}
	}()

	db := ls.handle()
	if db == nil {
		return
	}
	// Each of these writes for a while; incoming messages wait in the buffer.
	ls.gate.Lock()
	migrateSortIndexes(db)
	// The triggers keep the search index in step with the messages; it is
	// built once for a database from before them, not at every opening —
	// which took ten seconds a million messages, with writes waiting.
	if getMeta(db, metaFTSBuilt) == "" {
		var msgCount int64
		db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&msgCount)
		if msgCount > 0 {
			slog.Info("rebuilding FTS index", "messages", msgCount)
			if _, err := db.Exec("INSERT INTO messages_fts(messages_fts) VALUES('rebuild')"); err != nil {
				slog.Warn("FTS rebuild failed, text search may be slow", "error", err)
			}
			slog.Info("FTS index ready", "messages", msgCount)
		}
		setMeta(db, metaFTSBuilt, "1")
	}
	ls.gate.Unlock()
}

// BufferMessage adds a message to the write buffer (non-blocking).
func (ls *LogStore) BufferMessage(msg models.SyslogMessage) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if ls.db == nil || ls.readOnly {
		return
	}
	if len(ls.buffer) >= maxWriteBuffer {
		// Persistence can't keep up: drop the oldest to bound memory. Drop a
		// chunk at once (one memmove per chunk) rather than one element per
		// call — the latter is an O(n) copy of the whole 200k buffer on every
		// message, during the exact overload this guard exists for.
		drop := maxWriteBuffer / 8
		n := copy(ls.buffer, ls.buffer[drop:])
		ls.buffer = ls.buffer[:n]
		ls.droppedWrites += int64(drop)
		slog.Warn("log write buffer full, dropping oldest messages",
			"droppedThisChunk", drop, "droppedTotal", ls.droppedWrites)
	}
	ls.buffer = append(ls.buffer, msg)
}

// droppedWriteCount returns how many buffered messages have been dropped due
// to sustained buffer-full overload. Read under the same lock that mutates it.
func (ls *LogStore) droppedWriteCount() int64 {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	return ls.droppedWrites
}

func (ls *LogStore) flushLoop() {
	defer ls.wg.Done()
	ticker := time.NewTicker(logStoreFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ls.stopCh:
			if !ls.holding() {
				ls.flushWaiting() // the last one waits out a rewrite in progress
			}
			return
		case <-ticker.C:
			ls.flush()
		}
	}
}

func (ls *LogStore) flush() {
	// The whole database is being rewritten: the messages wait in the buffer
	// for the next tick rather than for the lock.
	if !ls.gate.TryRLock() {
		return
	}
	defer ls.gate.RUnlock()
	ls.write()
}

// flushWaiting writes the buffer once nothing rewrites the database.
func (ls *LogStore) flushWaiting() {
	ls.gate.RLock()
	defer ls.gate.RUnlock()
	ls.write()
}

func (ls *LogStore) write() {
	ls.mu.Lock()
	if len(ls.buffer) == 0 {
		ls.mu.Unlock()
		return
	}
	batch := ls.buffer
	ls.buffer = make([]models.SyslogMessage, 0, cap(batch))
	ls.mu.Unlock()

	db := ls.handle()
	if db == nil {
		return
	}
	// In transactions of writeChunk: after a pause — a compaction, a
	// restore — the buffer can hold tens of thousands of messages, and one
	// transaction of all of them would keep every other writer out for longer
	// than they wait.
	for i := 0; i < len(batch); i += writeChunk {
		if _, err := insertMessages(db, batch[i:min(i+writeChunk, len(batch))]); err != nil {
			// Put back, ahead of what came since, for the next tick: a write
			// that waited too long for the database is not a reason to lose
			// messages.
			slog.Warn("log store: write failed, will retry", "messages", len(batch)-i, "error", err)
			ls.requeue(batch[i:])
			return
		}
	}
}

// requeue puts messages a flush could not write back at the head of the
// buffer, within its cap.
func (ls *LogStore) requeue(batch []models.SyslogMessage) {
	ls.mu.Lock()
	defer ls.mu.Unlock()
	merged := append(batch, ls.buffer...)
	if over := len(merged) - maxWriteBuffer; over > 0 {
		merged = merged[over:]
		ls.droppedWrites += int64(over)
		slog.Warn("log write buffer full, dropping oldest messages",
			"droppedThisChunk", over, "droppedTotal", ls.droppedWrites)
	}
	ls.buffer = merged
}

// InsertMessages writes messages now rather than through the write buffer,
// and says whether they are on disk: the caller deletes its own copy once
// they are. A message already stored — same id — is left as it is, so
// writing a batch twice stores it once.
func (ls *LogStore) InsertMessages(msgs []models.SyslogMessage) error {
	_, err := ls.MergeMessages(msgs)
	return err
}

// MergeMessages is InsertMessages saying how many of the messages were not
// stored already: what merging a database into this one added.
func (ls *LogStore) MergeMessages(msgs []models.SyslogMessage) (int, error) {
	// Waits out a rewrite of the database rather than failing on it.
	ls.gate.RLock()
	defer ls.gate.RUnlock()
	db := ls.handle()
	if db == nil || ls.readOnly {
		return 0, ErrNotOpen
	}
	added := 0
	for i := 0; i < len(msgs); i += writeChunk {
		n, err := insertMessages(db, msgs[i:min(i+writeChunk, len(msgs))])
		if err != nil {
			return added, err
		}
		added += n
	}
	return added, nil
}

// insertMessages writes a batch in one transaction and says how many of its
// messages were new.
func insertMessages(db *sql.DB, batch []models.SyslogMessage) (int, error) {
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO messages
		(id, timestamp, received_at, severity, severity_label, facility, facility_label,
		 hostname, app_name, proc_id, msg_id, message, raw_message, source_ip, protocol,
		 version, structured_data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return 0, fmt.Errorf("prepare statement: %w", err)
	}
	defer stmt.Close()

	added := 0
	for _, msg := range batch {
		res, err := stmt.Exec(
			msg.ID,
			msg.Timestamp.UTC().Format(time.RFC3339Nano),
			msg.ReceivedAt.UTC().Format(time.RFC3339Nano),
			int(msg.Severity), msg.SeverityLabel,
			int(msg.Facility), msg.FacilityLabel,
			msg.Hostname, msg.AppName, msg.ProcID, msg.MsgID,
			msg.Message, msg.RawMessage,
			msg.SourceIP, msg.Protocol,
			msg.Version, msg.StructuredData,
		)
		if err != nil {
			// The whole batch or none of it: a row that did not go in —
			// most often a write that waited out the busy timeout — would
			// otherwise be lost while the caller is told the batch is stored.
			tx.Rollback()
			return 0, fmt.Errorf("insert %s: %w", msg.ID, err)
		}
		if n, _ := res.RowsAffected(); n > 0 {
			added++
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return added, nil
}

// WaitReady waits for the background index rebuild a store starts with: it
// writes to the database, and a long write of one's own meanwhile meets
// "database is locked".
func (ls *LogStore) WaitReady() {
	if ls.ftsReadyCh != nil {
		<-ls.ftsReadyCh
	}
}

// OldestMessages returns up to limit messages, the earliest received first.
// With DeleteMessages, it lets a database be emptied into somewhere else a
// batch at a time.
func (ls *LogStore) OldestMessages(limit int) ([]models.SyslogMessage, error) {
	db := ls.handle()
	if db == nil {
		return nil, fmt.Errorf("the database is not open")
	}
	rows, err := db.Query("SELECT id, timestamp, received_at, severity, severity_label, facility, facility_label, hostname, app_name, proc_id, msg_id, message, raw_message, source_ip, protocol, version, structured_data FROM messages ORDER BY received_at, id LIMIT ?", limit)
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

// DeleteMessages removes messages by id.
func (ls *LogStore) DeleteMessages(ids []string) error {
	db := ls.handle()
	if db == nil {
		return fmt.Errorf("the database is not open")
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	stmt, err := tx.Prepare("DELETE FROM messages WHERE id = ?")
	if err != nil {
		tx.Rollback()
		return err
	}
	defer stmt.Close()
	for _, id := range ids {
		if _, err := stmt.Exec(id); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// cleanupLoop applies the retention: the limits on count and size every
// cleanupEvery, the one on age then too or when its schedule says, and makes
// up a scheduled run missed while the store was closed.
func (ls *LogStore) cleanupLoop() {
	defer ls.wg.Done()
	ticker := time.NewTicker(cleanupTick)
	defer ticker.Stop()

	lastPass := time.Now()
	for {
		select {
		case <-ls.stopCh:
			return
		case now := <-ticker.C:
			db := ls.handle()
			if db == nil {
				continue
			}
			cfg := ls.currentConfig()
			ls.convertForSpaceReturn(db)
			due := false
			if cfg.Cleanup.Every != models.CleanupContinuous {
				last, _ := time.Parse(time.RFC3339, getMeta(db, metaLastScheduled))
				prev := PreviousRun(cfg.Cleanup, now)
				if last.IsZero() {
					// Just scheduled: from the next run on, not at once.
					setMeta(db, metaLastScheduled, now.Format(time.RFC3339))
				} else if last.Before(prev) {
					due = true
				}
			}
			if due || now.Sub(lastPass) >= cleanupEvery {
				lastPass = now
				ls.runCleanup(due)
			}
		}
	}
}

// runCleanup applies the retention once. scheduled says the age limit is due
// by the schedule; under a continuous one it always is.
func (ls *LogStore) runCleanup(scheduled bool) {
	db := ls.handle()
	if db == nil {
		return
	}
	cfg := ls.currentConfig()
	start := time.Now()
	fileBefore := ls.fileBytes()
	var deleted int64
	count := func(n int64, err error, what string) {
		deleted += n
		if err != nil {
			slog.Warn("log store: cleanup failed", "limit", what, "error", err)
		} else if n > 0 {
			slog.Info("log store: cleaned", "limit", what, "deleted", n)
		}
	}

	ageDue := cfg.Cleanup.Every == models.CleanupContinuous || scheduled
	if cfg.RetentionDays > 0 && ageDue {
		cutoff := retentionCutoff(start, cfg.RetentionDays, cfg.RetentionAlign)
		n, err := ls.deleteInChunks(db, " WHERE timestamp < ?", 0, sqlTime(cutoff))
		count(n, err, "age")
	}
	if cfg.MaxMessages > 0 {
		if excess := ls.messageCount(db) - int64(cfg.MaxMessages); excess > 0 {
			n, err := ls.deleteInChunks(db, "", excess)
			count(n, err, "count")
		}
	}
	if cfg.MaxSizeMB > 0 {
		n, err := ls.trimToSize(db, int64(cfg.MaxSizeMB)<<20)
		count(n, err, "size")
	}

	switch {
	case cfg.Compaction == models.CompactAuto:
		ls.giveBack(db)
	case cfg.Compaction == models.CompactAfterCleanup && scheduled:
		ls.rewrite(db, "VACUUM")
	}
	if deleted > 0 {
		// A large cleanup grows the write-ahead log by as much as it
		// deletes — 800 MB for a quarter of a million messages: folded back
		// into the database and truncated, whatever the compaction.
		db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	}
	if scheduled {
		setMeta(db, metaLastScheduled, start.Format(time.RFC3339))
	}
	if deleted > 0 {
		ls.mu.Lock()
		ls.forecastAt = time.Time{}
		ls.mu.Unlock()
	}
	if deleted > 0 || scheduled {
		freed := max(fileBefore-ls.fileBytes(), 0)
		record, _ := json.Marshal(models.CleanupRecord{
			At: start.Format(time.RFC3339), Deleted: deleted,
			FreedMB: float64(freed) / (1 << 20), TookMs: time.Since(start).Milliseconds(),
		})
		setMeta(db, metaLastCleanup, string(record))
	}
}

// fileBytes is what the database's files take on disk.
func (ls *LogStore) fileBytes() int64 {
	dbPath, _ := ResolveDBPath(ls.currentConfig().Path)
	var total int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if info, err := os.Stat(dbPath + suffix); err == nil {
			total += info.Size()
		}
	}
	return total
}

// trimToSize deletes the oldest messages until what the rows take is back under
// limit, aiming a tenth below it so the next pass does not start over at once.
// Deleting rows leaves index pages part-empty rather than free, so the space
// comes back less than in proportion: it checks and goes again, a few times at
// most.
func (ls *LogStore) trimToSize(db *sql.DB, limit int64) (int64, error) {
	target := limit - limit/10
	var total int64
	for pass := 0; pass < 5; pass++ {
		used := ls.usedBytes(db)
		if used <= limit {
			break
		}
		count := ls.messageCount(db)
		if count == 0 {
			break
		}
		// What to delete for the rest to fit, at the average row's size.
		toDelete := count - count*target/used
		if toDelete < 1 {
			toDelete = 1
		}
		n, err := ls.deleteInChunks(db, "", toDelete)
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// QueryMessages returns a paginated, filtered, sorted result set.
func (ls *LogStore) QueryMessages(opts models.QueryOptions) models.PagedResult {
	page := opts.Page
	pageSize := opts.PageSize
	db := ls.handle()
	if db == nil {
		return models.PagedResult{Page: page, PageSize: pageSize}
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	f := search.CompileFilter(opts.Filter)
	plan := &f.Plan
	where, args := buildWhereClause(&f)
	orderBy := buildOrderClause(opts.SortField, opts.SortDir)

	// A regex is applied after the query, in Go: SQLite has no REGEXP.
	if plan.NeedsScan() {
		// Two-pass approach for performance:
		// Pass 1: scan only id + message + raw_message (lightweight) -> collect matching IDs
		// Pass 2: fetch full rows only for the current page

		var totalRows int
		db.QueryRow("SELECT COUNT(*) FROM messages"+where, args...).Scan(&totalRows)

		if ls.emitter != nil {
			ls.emitter.Emit("syslog:queryProgress", map[string]interface{}{"scanned": 0, "total": totalRows, "matched": 0})
		}

		// Pass 1: lightweight scan (id + message + raw_message)
		scanSQL := "SELECT id, message, raw_message FROM messages" + where + orderBy
		rows, err := db.Query(scanSQL, args...)
		if err != nil {
			slog.Error("log store: regex scan failed", "error", err)
			return models.PagedResult{Page: page, PageSize: pageSize}
		}

		var matchedIDs []string
		scanned := 0
		for rows.Next() {
			var id, msg, rawMsg string
			if rows.Scan(&id, &msg, &rawMsg) != nil {
				continue
			}
			scanned++
			if plan.Match(msg, rawMsg) {
				matchedIDs = append(matchedIDs, id)
			}
			if ls.emitter != nil && scanned%5000 == 0 {
				ls.emitter.Emit("syslog:queryProgress", map[string]interface{}{
					"scanned": scanned, "total": totalRows, "matched": len(matchedIDs),
				})
			}
		}
		rows.Close()

		if ls.emitter != nil {
			ls.emitter.Emit("syslog:queryProgress", map[string]interface{}{
				"scanned": totalRows, "total": totalRows, "matched": len(matchedIDs), "done": true,
			})
		}

		total := len(matchedIDs)
		offset := (page - 1) * pageSize
		end := offset + pageSize
		if offset > total {
			offset = total
		}
		if end > total {
			end = total
		}

		// Pass 2: fetch full data for this page only
		var messages []models.SyslogMessage
		if offset < end {
			pageIDs := matchedIDs[offset:end]
			placeholders := make([]string, len(pageIDs))
			fetchArgs := make([]interface{}, len(pageIDs))
			for i, id := range pageIDs {
				placeholders[i] = "?"
				fetchArgs[i] = id
			}
			fetchSQL := "SELECT id, timestamp, received_at, severity, severity_label, facility, facility_label, hostname, app_name, proc_id, msg_id, message, raw_message, source_ip, protocol, version, structured_data FROM messages WHERE id IN (" + strings.Join(placeholders, ",") + ")" + orderBy
			fetchRows, err := db.Query(fetchSQL, fetchArgs...)
			if err == nil {
				defer fetchRows.Close()
				for fetchRows.Next() {
					msg := ls.scanMessage(fetchRows)
					if msg != nil {
						messages = append(messages, *msg)
					}
				}
			}
		}

		return models.PagedResult{
			Messages: messages,
			Total:    total,
			Page:     page,
			PageSize: pageSize,
		}
	}

	// Standard mode: SQL handles everything
	var total int
	db.QueryRow("SELECT COUNT(*) FROM messages"+where, args...).Scan(&total)

	offset := (page - 1) * pageSize
	querySQL := "SELECT id, timestamp, received_at, severity, severity_label, facility, facility_label, hostname, app_name, proc_id, msg_id, message, raw_message, source_ip, protocol, version, structured_data FROM messages" + where + orderBy + " LIMIT ? OFFSET ?"
	queryArgs := append(args, pageSize, offset)

	rows, err := db.Query(querySQL, queryArgs...)
	if err != nil {
		slog.Error("log store: query failed", "error", err)
		return models.PagedResult{Page: page, PageSize: pageSize, Total: total}
	}
	defer rows.Close()

	var messages []models.SyslogMessage
	for rows.Next() {
		msg := ls.scanMessage(rows)
		if msg != nil {
			messages = append(messages, *msg)
		}
	}

	return models.PagedResult{
		Messages: messages,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}
}

func (ls *LogStore) scanMessage(rows *sql.Rows) *models.SyslogMessage {
	var msg models.SyslogMessage
	var tsStr, raStr string
	err := rows.Scan(
		&msg.ID, &tsStr, &raStr,
		&msg.Severity, &msg.SeverityLabel,
		&msg.Facility, &msg.FacilityLabel,
		&msg.Hostname, &msg.AppName, &msg.ProcID, &msg.MsgID,
		&msg.Message, &msg.RawMessage,
		&msg.SourceIP, &msg.Protocol,
		&msg.Version, &msg.StructuredData,
	)
	if err != nil {
		return nil
	}
	msg.Timestamp, _ = time.Parse(time.RFC3339Nano, tsStr)
	msg.ReceivedAt, _ = time.Parse(time.RFC3339Nano, raStr)
	return &msg
}

// QueryGroups returns message counts grouped by a field.
func (ls *LogStore) QueryGroups(filter models.FilterCriteria, groupField string) []models.GroupSummary {
	db := ls.handle()
	if db == nil {
		return nil
	}
	col, ok := groupColumns[groupField]
	if !ok {
		return nil
	}

	f := search.CompileFilter(filter)
	where, args := buildWhereClause(&f)
	// Biggest first, then by name, as the live view orders its groups. A
	// regex is not applied here: counting would mean reading every row.
	query := "SELECT " + col + ", COUNT(*) FROM messages" + where + " GROUP BY " + col +
		" ORDER BY COUNT(*) DESC, " + col + " COLLATE NOCASE, " + col
	rows, err := db.Query(query, args...)
	if err != nil {
		slog.Error("log store: group query failed", "error", err)
		return nil
	}
	defer rows.Close()

	var groups []models.GroupSummary
	for rows.Next() {
		var g models.GroupSummary
		// The key as it is, "" included: it is what picks the group's
		// messages when the group is opened.
		if err := rows.Scan(&g.Key, &g.Count); err == nil {
			groups = append(groups, g)
		}
	}
	return groups
}

// GetStats returns storage statistics.
func (ls *LogStore) GetStats() models.StorageStats {
	db := ls.handle()
	if db == nil {
		return models.StorageStats{}
	}

	cfg := ls.currentConfig()
	used := ls.usedBytes(db)
	file := ls.fileBytes()
	stats := models.StorageStats{
		MessageCount:   ls.messageCount(db),
		DroppedWrites:  ls.droppedWriteCount(),
		DatabaseSizeMB: float64(file) / (1 << 20),
		UsedMB:         float64(used) / (1 << 20),
		SpaceReturns:   spaceReturns(db),
		LastCleanup:    lastCleanup(db),
	}
	ls.mu.Lock()
	stats.Compacting = ls.compacting
	ls.mu.Unlock()
	now := time.Now()
	stats.NextCleanup = formatRFC3339(NextRun(cfg.Cleanup, now))
	ls.mu.Lock()
	cached, at := ls.forecast, ls.forecastAt
	ls.mu.Unlock()
	if now.Sub(at) < forecastFor {
		stats.Forecast = cached
	} else {
		stats.Forecast = forecast(db, cfg, now, stats.MessageCount, used, file, dbDir(cfg.Path))
		ls.mu.Lock()
		ls.forecast, ls.forecastAt = stats.Forecast, now
		ls.mu.Unlock()
	}

	// Oldest message
	var oldest sql.NullString
	db.QueryRow("SELECT MIN(timestamp) FROM messages").Scan(&oldest)
	if oldest.Valid {
		stats.OldestTimestamp = oldest.String
	}

	return stats
}

// messageCount takes the handle from its caller so a single GetStats/runCleanup
// pass uses one consistent handle rather than re-reading ls.db mid-operation.
func (ls *LogStore) messageCount(db *sql.DB) int64 {
	var count int64
	db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	return count
}

// usedBytes is the space the rows and their index take, which is what the size
// cap is about. The file is no measure of it: SQLite keeps the pages of deleted
// rows in the file, on a free list for later inserts, until a VACUUM.
func (ls *LogStore) usedBytes(db *sql.DB) int64 {
	var pages, free, size int64
	if db.QueryRow("PRAGMA page_count").Scan(&pages) != nil ||
		db.QueryRow("PRAGMA freelist_count").Scan(&free) != nil ||
		db.QueryRow("PRAGMA page_size").Scan(&size) != nil {
		return 0
	}
	return (pages - free) * size
}

// Compact runs VACUUM to reclaim disk space.
func (ls *LogStore) Compact() error {
	db := ls.handle()
	if db == nil {
		return nil
	}
	return ls.rewrite(db, "VACUUM")
}

// ClearAll deletes all messages and compacts the database.
func (ls *LogStore) ClearAll() error {
	db := ls.handle()
	if db == nil {
		return nil
	}
	ls.gate.Lock()
	_, err := db.Exec("DELETE FROM messages")
	ls.gate.Unlock()
	if err != nil {
		return err
	}
	return ls.Compact()
}

// UpdateConfig updates the storage configuration (for retention changes).
//
// A configuration with no path keeps the store's own. The path decides which
// file Close encrypts and deletes, and an empty one resolves to the user's
// default database: an engine with a data directory of its own — a test's —
// once encrypted a real user's database on closing.
func (ls *LogStore) UpdateConfig(config models.StorageConfig) {
	ls.mu.Lock()
	if config.Path == "" {
		config.Path = ls.config.Path
	}
	ls.config = config
	ls.forecastAt = time.Time{} // the forecast follows the settings
	ls.mu.Unlock()
}

// Close flushes remaining messages, closes the database, and encrypts if enabled.
func (ls *LogStore) Close() {
	db := ls.handle()
	if db == nil {
		return
	}
	if ls.readOnly {
		db.Close()
		ls.mu.Lock()
		ls.db = nil
		ls.mu.Unlock()
		return
	}

	// Wait for background FTS rebuild to finish before closing
	if ls.ftsReadyCh != nil {
		<-ls.ftsReadyCh
	}

	close(ls.stopCh)
	ls.wg.Wait()
	// The write-ahead log folded into the database, so that one file is all
	// there is to encrypt. This used to be a VACUUM, which rewrote the whole
	// database at every closing — over ten seconds a million messages.
	db.Exec("PRAGMA wal_checkpoint(TRUNCATE)")
	db.Close()
	// Clear the field under the lock: readers take it via handle(), so an
	// unsynchronized write here would race with an in-flight frontend query.
	ls.mu.Lock()
	ls.db = nil
	ls.mu.Unlock()

	// Encrypt at rest if enabled
	slog.Info("log store: close encryption check",
		"encryptionEnabled", ls.config.EncryptionEnabled,
		"hasPassword", ls.encryptionPassword != "")
	if ls.config.EncryptionEnabled && ls.encryptionPassword != "" {
		dbPath, err := ResolveDBPath(ls.config.Path)
		if err != nil {
			slog.Error("encrypt: failed to resolve DB path", "error", err)
			return
		}

		// Clean up WAL/SHM (the checkpoint already consolidated them)
		os.Remove(dbPath + "-wal")
		os.Remove(dbPath + "-shm")

		// A chunk at a time, in the vault format: the memory taken no longer
		// grows with the database. The file appears whole or not at all.
		encPath := dbPath + ".enc"
		size := fileSize(dbPath)
		err = vault.EncryptFile(dbPath, encPath, ls.encryptionPassword, vault.Header{Kind: vault.KindDatabase}, func(done int64) {
			ls.emitCryptoProgress(CryptoProgress{Phase: "encrypting", Percent: percentOf(done, size), SizeMB: float64(size) / (1 << 20)})
		})
		if err == nil {
			ls.emitCryptoProgress(CryptoProgress{Phase: "done", Percent: 100, SizeMB: float64(size) / (1 << 20)})
		}
		if err != nil {
			slog.Error("failed to encrypt database, leaving plaintext", "error", err)
			return
		}

		// Only delete plaintext after successful encryption
		os.Remove(dbPath)
		slog.Info("database encrypted at rest", "path", encPath)
	}

	slog.Info("log store closed")
}

func fileSize(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}

func percentOf(done, total int64) float64 {
	if total <= 0 {
		return 100
	}
	return min(100, float64(done)*100/float64(total))
}
