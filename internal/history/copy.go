// Package history copies stored messages from one database into another: a
// backup merged into the database, the history of a window brought to the
// service it installs, the service's brought back before it is removed, or
// into the encrypted database of a window that makes it seal.
//
// A message is known by its id, which the sink keeps once: a copy that stops
// half way is taken up again — from where it stopped, or from the start —
// and adds nothing twice.
package history

import (
	"context"
	"fmt"

	"SyslogStudio/internal/models"
)

// Source is a database read a batch at a time, in the order it was written
// (storage.LogStore, the engine, or the service through its pipe).
type Source interface {
	MessagesAfter(after int64, limit int) ([]models.SyslogMessage, int64, error)
}

// Sink is a database messages are merged into: it says how many were new.
type Sink interface {
	MergeMessages(msgs []models.SyslogMessage) (int, error)
}

// batch is how many messages one step reads and writes: about a megabyte,
// which is what crosses the service's pipe at once. Tests make it smaller,
// for many batches without thousands of messages.
var batch = 2000

// Progress is how far a copy has got.
type Progress struct {
	// Read is how many messages were read, Added how many of them the sink
	// did not hold already.
	Read  int64 `json:"read"`
	Added int64 `json:"added"`
	// Cursor is where the source stands: a copy from it carries on.
	Cursor int64 `json:"-"`
}

// Copy merges what src holds after from.Cursor into dst, a batch at a time,
// counting on from from, and reports after each batch. It runs to the end of
// src — messages written meanwhile included — and stops early when ctx is
// done or at the first error, saying how far it got: a Copy from there
// carries on.
func Copy(ctx context.Context, src Source, dst Sink, from Progress, report func(Progress)) (Progress, error) {
	p := from
	for {
		if err := ctx.Err(); err != nil {
			return p, err
		}
		msgs, next, err := src.MessagesAfter(p.Cursor, batch)
		if err != nil {
			return p, fmt.Errorf("read the messages to copy: %w", err)
		}
		if next <= p.Cursor {
			return p, nil
		}
		added, err := dst.MergeMessages(msgs)
		if err != nil {
			return p, fmt.Errorf("store the messages copied: %w", err)
		}
		p.Read += int64(len(msgs))
		p.Added += int64(added)
		p.Cursor = next
		if report != nil {
			report(p)
		}
	}
}
