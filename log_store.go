package main

import (
	"database/sql"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

const (
	logStoreFlushInterval   = 500 * time.Millisecond
	logStoreCleanupInterval = 5 * time.Minute
	dbFileName              = "logs.db"
)

// LogStore handles SQLite-based message persistence.
type LogStore struct {
	mu      sync.Mutex
	db      *sql.DB
	config  StorageConfig
	buffer  []SyslogMessage
	emitter EventEmitter

	stopCh chan struct{}
	wg     sync.WaitGroup
}

// NewLogStore creates and initializes a LogStore.
func NewLogStore(config StorageConfig, emitter EventEmitter) (*LogStore, error) {
	if !config.Enabled {
		return &LogStore{config: config}, nil
	}

	dbPath, err := resolveDBPath(config.Path)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DB path: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(dbPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create DB directory: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+
		"?_pragma=journal_mode(wal)"+
		"&_pragma=synchronous(normal)"+
		"&_pragma=busy_timeout(5000)"+
		"&_pragma=cache_size(-64000)"+ // 64 MB cache (vs 2 MB default)
		"&_pragma=mmap_size(268435456)"+ // 256 MB memory-mapped I/O
		"&_pragma=temp_store(memory)") // temp tables in RAM
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// WAL mode allows concurrent readers, only writes need serialization
	db.SetMaxOpenConns(4)

	if err := initSchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to init schema: %w", err)
	}

	ls := &LogStore{
		db:      db,
		config:  config,
		buffer:  make([]SyslogMessage, 0, 256),
		emitter: emitter,
		stopCh:  make(chan struct{}),
	}

	ls.wg.Add(2)
	go ls.flushLoop()
	go ls.cleanupLoop()

	slog.Info("log store initialized", "path", dbPath)
	return ls, nil
}

func resolveDBPath(configPath string) (string, error) {
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
	CREATE INDEX IF NOT EXISTS idx_hostname ON messages(hostname);
	CREATE INDEX IF NOT EXISTS idx_app_name ON messages(app_name);
	CREATE INDEX IF NOT EXISTS idx_source_ip ON messages(source_ip);

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
	if err != nil {
		return err
	}

	// Rebuild FTS index at startup to ensure sync with main table.
	// This is idempotent and fast (~1s per 100k messages).
	var msgCount int64
	db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&msgCount)
	if msgCount > 0 {
		slog.Info("rebuilding FTS index", "messages", msgCount)
		if _, err = db.Exec("INSERT INTO messages_fts(messages_fts) VALUES('rebuild')"); err != nil {
			slog.Warn("FTS rebuild failed, text search may be slow", "error", err)
		}
	}

	return nil
}

// BufferMessage adds a message to the write buffer (non-blocking).
func (ls *LogStore) BufferMessage(msg SyslogMessage) {
	if ls.db == nil {
		return
	}
	ls.mu.Lock()
	ls.buffer = append(ls.buffer, msg)
	ls.mu.Unlock()
}

func (ls *LogStore) flushLoop() {
	defer ls.wg.Done()
	ticker := time.NewTicker(logStoreFlushInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ls.stopCh:
			ls.flush() // final flush
			return
		case <-ticker.C:
			ls.flush()
		}
	}
}

func (ls *LogStore) flush() {
	ls.mu.Lock()
	if len(ls.buffer) == 0 {
		ls.mu.Unlock()
		return
	}
	batch := ls.buffer
	ls.buffer = make([]SyslogMessage, 0, cap(batch))
	ls.mu.Unlock()

	tx, err := ls.db.Begin()
	if err != nil {
		slog.Error("log store: failed to begin transaction", "error", err)
		return
	}

	stmt, err := tx.Prepare(`INSERT OR IGNORE INTO messages
		(id, timestamp, received_at, severity, severity_label, facility, facility_label,
		 hostname, app_name, proc_id, msg_id, message, raw_message, source_ip, protocol,
		 version, structured_data)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		slog.Error("log store: failed to prepare statement", "error", err)
		return
	}
	defer stmt.Close()

	for _, msg := range batch {
		_, err := stmt.Exec(
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
			slog.Debug("log store: insert error", "id", msg.ID, "error", err)
		}
	}

	if err := tx.Commit(); err != nil {
		slog.Error("log store: commit failed", "error", err)
	}
}

func (ls *LogStore) cleanupLoop() {
	defer ls.wg.Done()
	ticker := time.NewTicker(logStoreCleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ls.stopCh:
			return
		case <-ticker.C:
			ls.runCleanup()
		}
	}
}

func (ls *LogStore) runCleanup() {
	if ls.db == nil {
		return
	}

	// Retention by age
	if ls.config.RetentionDays > 0 {
		cutoff := time.Now().Add(-time.Duration(ls.config.RetentionDays) * 24 * time.Hour).UTC().Format(time.RFC3339)
		res, err := ls.db.Exec("DELETE FROM messages WHERE timestamp < ?", cutoff)
		if err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				slog.Info("log store: cleaned old messages", "deleted", n)
			}
		}
	}

	// Retention by count
	if ls.config.MaxMessages > 0 {
		res, err := ls.db.Exec(`DELETE FROM messages WHERE id IN (
			SELECT id FROM messages ORDER BY timestamp ASC
			LIMIT MAX(0, (SELECT COUNT(*) FROM messages) - ?)
		)`, ls.config.MaxMessages)
		if err == nil {
			if n, _ := res.RowsAffected(); n > 0 {
				slog.Info("log store: trimmed by count", "deleted", n)
			}
		}
	}

	// Retention by size
	if ls.config.MaxSizeMB > 0 {
		stats := ls.GetStats()
		if stats.DatabaseSizeMB > float64(ls.config.MaxSizeMB) {
			// Delete oldest 10% to make room
			count := ls.messageCount()
			toDelete := count / 10
			if toDelete < 1000 {
				toDelete = 1000
			}
			ls.db.Exec("DELETE FROM messages WHERE id IN (SELECT id FROM messages ORDER BY timestamp ASC LIMIT ?)", toDelete)
			slog.Info("log store: trimmed by size", "deleted", toDelete)
		}
	}
}

var allowedSortFields = map[string]string{
	"timestamp": "timestamp",
	"severity":  "severity",
	"hostname":  "hostname",
	"appName":   "app_name",
	"sourceIP":  "source_ip",
	"protocol":  "protocol",
	"message":   "message",
}

var allowedGroupFields = map[string]string{
	"severity": "severity_label",
	"hostname": "hostname",
	"appName":  "app_name",
	"sourceIP": "source_ip",
}

func buildOrderClause(sortField, sortDir string) string {
	col, ok := allowedSortFields[sortField]
	if !ok {
		col = "timestamp"
	}
	dir := "DESC"
	if sortDir == "asc" {
		dir = "ASC"
	}
	return " ORDER BY " + col + " " + dir
}

// QueryMessages returns a paginated, filtered, sorted result set.
func (ls *LogStore) QueryMessages(opts QueryOptions) PagedResult {
	page := opts.Page
	pageSize := opts.PageSize
	if ls.db == nil {
		return PagedResult{Page: page, PageSize: pageSize}
	}
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 1000 {
		pageSize = 100
	}

	where, args := buildWhereClause(opts.Filter)
	orderBy := buildOrderClause(opts.SortField, opts.SortDir)

	// Regex search requires post-query filtering
	useRegexFilter := opts.Filter.SearchMode == "regex" && opts.Filter.Search != ""
	var regexFilter *regexp.Regexp
	if useRegexFilter {
		var err error
		regexFilter, err = safeCompileRegex(opts.Filter.Search)
		if err != nil {
			useRegexFilter = false // invalid regex, skip
		}
	}

	if useRegexFilter {
		// Two-pass approach for performance:
		// Pass 1: scan only id + message + raw_message (lightweight) → collect matching IDs
		// Pass 2: fetch full rows only for the current page

		var totalRows int
		ls.db.QueryRow("SELECT COUNT(*) FROM messages"+where, args...).Scan(&totalRows)

		if ls.emitter != nil {
			ls.emitter.Emit("syslog:queryProgress", map[string]interface{}{"scanned": 0, "total": totalRows, "matched": 0})
		}

		// Pass 1: lightweight scan (id + message + raw_message)
		scanSQL := "SELECT id, message, raw_message FROM messages" + where + orderBy
		rows, err := ls.db.Query(scanSQL, args...)
		if err != nil {
			slog.Error("log store: regex scan failed", "error", err)
			return PagedResult{Page: page, PageSize: pageSize}
		}

		var matchedIDs []string
		scanned := 0
		for rows.Next() {
			var id, msg, rawMsg string
			if rows.Scan(&id, &msg, &rawMsg) != nil {
				continue
			}
			scanned++
			if regexFilter.MatchString(msg) || regexFilter.MatchString(rawMsg) {
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
		var messages []SyslogMessage
		if offset < end {
			pageIDs := matchedIDs[offset:end]
			placeholders := make([]string, len(pageIDs))
			fetchArgs := make([]interface{}, len(pageIDs))
			for i, id := range pageIDs {
				placeholders[i] = "?"
				fetchArgs[i] = id
			}
			fetchSQL := "SELECT id, timestamp, received_at, severity, severity_label, facility, facility_label, hostname, app_name, proc_id, msg_id, message, raw_message, source_ip, protocol, version, structured_data FROM messages WHERE id IN (" + strings.Join(placeholders, ",") + ")" + orderBy
			fetchRows, err := ls.db.Query(fetchSQL, fetchArgs...)
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

		return PagedResult{
			Messages: messages,
			Total:    total,
			Page:     page,
			PageSize: pageSize,
		}
	}

	// Standard mode: SQL handles everything
	var total int
	ls.db.QueryRow("SELECT COUNT(*) FROM messages"+where, args...).Scan(&total)

	offset := (page - 1) * pageSize
	querySQL := "SELECT id, timestamp, received_at, severity, severity_label, facility, facility_label, hostname, app_name, proc_id, msg_id, message, raw_message, source_ip, protocol, version, structured_data FROM messages" + where + orderBy + " LIMIT ? OFFSET ?"
	queryArgs := append(args, pageSize, offset)

	rows, err := ls.db.Query(querySQL, queryArgs...)
	if err != nil {
		slog.Error("log store: query failed", "error", err)
		return PagedResult{Page: page, PageSize: pageSize, Total: total}
	}
	defer rows.Close()

	var messages []SyslogMessage
	for rows.Next() {
		msg := ls.scanMessage(rows)
		if msg != nil {
			messages = append(messages, *msg)
		}
	}

	return PagedResult{
		Messages: messages,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	}
}

func (ls *LogStore) scanMessage(rows *sql.Rows) *SyslogMessage {
	var msg SyslogMessage
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
func (ls *LogStore) QueryGroups(filter FilterCriteria, groupField string) []GroupSummary {
	if ls.db == nil {
		return nil
	}
	col, ok := allowedGroupFields[groupField]
	if !ok {
		return nil
	}

	where, args := buildWhereClause(filter)
	query := "SELECT " + col + ", COUNT(*) FROM messages" + where + " GROUP BY " + col + " ORDER BY COUNT(*) DESC"
	rows, err := ls.db.Query(query, args...)
	if err != nil {
		slog.Error("log store: group query failed", "error", err)
		return nil
	}
	defer rows.Close()

	var groups []GroupSummary
	for rows.Next() {
		var g GroupSummary
		if err := rows.Scan(&g.Key, &g.Count); err == nil {
			if g.Key == "" {
				g.Key = "unknown"
			}
			groups = append(groups, g)
		}
	}
	return groups
}

// ftsEscapeQuery converts a user search string into a safe FTS5 query.
// Each word becomes a prefix search term, joined with AND.
// e.g. "connection refused" → "connection* AND refused*"
func ftsEscapeQuery(input string) string {
	words := strings.Fields(input)
	if len(words) == 0 {
		return ""
	}
	escaped := make([]string, len(words))
	for i, w := range words {
		// Remove FTS5 special characters
		clean := strings.NewReplacer(
			"\"", "", "'", "", "(", "", ")", "",
			"*", "", ":", "", "^", "", "{", "", "}", "",
		).Replace(w)
		if clean == "" {
			clean = w
		}
		escaped[i] = "\"" + clean + "\"" + "*"
	}
	return strings.Join(escaped, " AND ")
}

func buildWhereClause(filter FilterCriteria) (string, []interface{}) {
	var conditions []string
	var args []interface{}

	if len(filter.Severities) > 0 {
		placeholders := make([]string, len(filter.Severities))
		for i, s := range filter.Severities {
			placeholders[i] = "?"
			args = append(args, s)
		}
		conditions = append(conditions, "severity IN ("+strings.Join(placeholders, ",")+")")
	}

	if len(filter.Facilities) > 0 {
		placeholders := make([]string, len(filter.Facilities))
		for i, f := range filter.Facilities {
			placeholders[i] = "?"
			args = append(args, f)
		}
		conditions = append(conditions, "facility IN ("+strings.Join(placeholders, ",")+")")
	}

	if filter.Hostname != "" {
		conditions = append(conditions, "hostname LIKE ?")
		args = append(args, "%"+filter.Hostname+"%")
	}
	if filter.AppName != "" {
		conditions = append(conditions, "app_name LIKE ?")
		args = append(args, "%"+filter.AppName+"%")
	}
	if filter.SourceIP != "" {
		conditions = append(conditions, "source_ip LIKE ?")
		args = append(args, "%"+filter.SourceIP+"%")
	}
	if filter.Search != "" && filter.SearchMode != "regex" {
		if filter.SearchMode == "fts" {
			// FTS advanced mode: pass query directly to FTS5 (user writes OR, AND, NOT, "phrases", prefix*)
			conditions = append(conditions, "rowid IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)")
			args = append(args, filter.Search)
		} else {
			// Text mode: auto-escape for safe FTS5 search
			ftsQuery := ftsEscapeQuery(filter.Search)
			if ftsQuery != "" {
				conditions = append(conditions, "rowid IN (SELECT rowid FROM messages_fts WHERE messages_fts MATCH ?)")
				args = append(args, ftsQuery)
			}
		}
	}
	// Regex search is applied post-query in Go (SQLite doesn't support REGEXP)
	if filter.DateFrom != "" {
		conditions = append(conditions, "timestamp >= ?")
		args = append(args, filter.DateFrom)
	}
	if filter.DateTo != "" {
		conditions = append(conditions, "timestamp <= ?")
		args = append(args, filter.DateTo)
	}

	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}

// GetStats returns storage statistics.
func (ls *LogStore) GetStats() StorageStats {
	if ls.db == nil {
		return StorageStats{}
	}

	stats := StorageStats{
		MessageCount: ls.messageCount(),
	}

	// DB file size (main + WAL + SHM)
	dbPath, _ := resolveDBPath(ls.config.Path)
	var totalBytes int64
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if info, err := os.Stat(dbPath + suffix); err == nil {
			totalBytes += info.Size()
		}
	}
	stats.DatabaseSizeMB = float64(totalBytes) / (1024 * 1024)

	// Oldest message
	var oldest sql.NullString
	ls.db.QueryRow("SELECT MIN(timestamp) FROM messages").Scan(&oldest)
	if oldest.Valid {
		stats.OldestTimestamp = oldest.String
	}

	return stats
}

func (ls *LogStore) messageCount() int64 {
	var count int64
	ls.db.QueryRow("SELECT COUNT(*) FROM messages").Scan(&count)
	return count
}

// Compact runs VACUUM to reclaim disk space.
func (ls *LogStore) Compact() error {
	if ls.db == nil {
		return nil
	}
	slog.Info("log store: running VACUUM")
	_, err := ls.db.Exec("VACUUM")
	return err
}

// ClearAll deletes all messages and compacts the database.
func (ls *LogStore) ClearAll() error {
	if ls.db == nil {
		return nil
	}
	if _, err := ls.db.Exec("DELETE FROM messages"); err != nil {
		return err
	}
	return ls.Compact()
}

// UpdateConfig updates the storage configuration (for retention changes).
func (ls *LogStore) UpdateConfig(config StorageConfig) {
	ls.mu.Lock()
	ls.config = config
	ls.mu.Unlock()
}

// Close flushes remaining messages and closes the database.
func (ls *LogStore) Close() {
	if ls.db == nil {
		return
	}
	close(ls.stopCh)
	ls.wg.Wait()
	ls.Compact()
	ls.db.Close()
	slog.Info("log store closed")
}
