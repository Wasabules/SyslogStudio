package storage

import (
	"database/sql"
	"fmt"
	"time"

	"SyslogStudio/internal/models"
)

// Reading stored messages again (engine/reread.go): a pass over what was
// stored when it began, and their readings rewritten in place.

// Extent says how many messages are stored, and the rowid of the last one.
func (ls *LogStore) Extent() (count, last int64, err error) {
	db := ls.handle()
	if db == nil {
		return 0, 0, ErrNotOpen
	}
	var lastRow sql.NullInt64
	err = db.QueryRow("SELECT count(*), MAX(rowid) FROM messages").Scan(&count, &lastRow)
	return count, lastRow.Int64, err
}

// MessagesUpTo is MessagesAfter that ends at the rowid last: a pass over what
// was stored when it began, which what arrives meanwhile does not prolong.
func (ls *LogStore) MessagesUpTo(after, last int64, limit int) ([]models.SyslogMessage, int64, error) {
	db := ls.handle()
	if db == nil {
		return nil, after, ErrNotOpen
	}
	var upTo sql.NullInt64
	err := db.QueryRow("SELECT MAX(rowid) FROM (SELECT rowid FROM messages WHERE rowid > ? AND rowid <= ? ORDER BY rowid LIMIT ?)",
		after, last, limit).Scan(&upTo)
	if err != nil || !upTo.Valid {
		return nil, after, err
	}
	msgs, err := ls.messagesBetween(db, after, upTo.Int64)
	if err != nil {
		return nil, after, err
	}
	return msgs, upTo.Int64, nil
}

// RewriteReadings replaces what was read of stored messages, found by id:
// their time, levels, host, application, ids, text and structured data. The
// raw message, the source, the protocol and the arrival stay, so the message
// can always be read again. The search index follows the text. It says how
// many it found.
func (ls *LogStore) RewriteReadings(msgs []models.SyslogMessage) (int, error) {
	// Waits out a rewrite of the database, the search index's building
	// included: an index built meanwhile is built from what this leaves.
	ls.gate.RLock()
	defer ls.gate.RUnlock()
	db := ls.handle()
	if db == nil || ls.readOnly {
		return 0, ErrNotOpen
	}
	tx, err := db.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()
	update, err := tx.Prepare(`UPDATE messages SET timestamp = ?, severity = ?, severity_label = ?,
		facility = ?, facility_label = ?, hostname = ?, app_name = ?, proc_id = ?, msg_id = ?,
		message = ?, version = ?, structured_data = ? WHERE rowid = ?`)
	if err != nil {
		return 0, err
	}
	defer update.Close()
	found := 0
	for _, m := range msgs {
		var rowid int64
		var oldText, raw string
		err := tx.QueryRow("SELECT rowid, message, raw_message FROM messages WHERE id = ?", m.ID).Scan(&rowid, &oldText, &raw)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return found, err
		}
		// The index has no trigger for an update: the text it holds goes
		// out, the new one in, as the insert and delete triggers do it.
		if m.Message != oldText {
			if _, err := tx.Exec("INSERT INTO messages_fts(messages_fts, rowid, message, raw_message) VALUES ('delete', ?, ?, ?)",
				rowid, oldText, raw); err != nil {
				return found, err
			}
		}
		if _, err := update.Exec(m.Timestamp.UTC().Format(time.RFC3339Nano), int(m.Severity), m.SeverityLabel,
			int(m.Facility), m.FacilityLabel, m.Hostname, m.AppName, m.ProcID, m.MsgID,
			m.Message, m.Version, m.StructuredData, rowid); err != nil {
			return found, err
		}
		if m.Message != oldText {
			if _, err := tx.Exec("INSERT INTO messages_fts(rowid, message, raw_message) VALUES (?, ?, ?)",
				rowid, m.Message, raw); err != nil {
				return found, err
			}
		}
		found++
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	return found, nil
}
