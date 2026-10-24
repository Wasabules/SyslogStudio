package engine

// The database read and written a batch at a time, for what copies messages
// between databases (package history): a window and the service it drives
// each read and merge through these, the service over its pipe.

import (
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
)

// maxReadBatch bounds what one MessagesAfter returns, whatever is asked.
const maxReadBatch = 5000

// MessagesAfter reads up to limit stored messages written after the cursor
// after, and says where the next read starts.
func (e *Engine) MessagesAfter(after int64, limit int) ([]models.SyslogMessage, int64, error) {
	if e.logStore == nil || e.IsEncryptionLocked() {
		return nil, after, storage.ErrNotOpen
	}
	return e.logStore.MessagesAfter(after, max(1, min(limit, maxReadBatch)))
}

// MergeMessages stores messages now — not through the write buffer — and
// says how many were not there already. They are history: they reach
// neither the live view nor the rules.
func (e *Engine) MergeMessages(msgs []models.SyslogMessage) (int, error) {
	if e.logStore == nil || e.IsEncryptionLocked() {
		return 0, storage.ErrNotOpen
	}
	return e.logStore.MergeMessages(msgs)
}
