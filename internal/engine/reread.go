package engine

// Reading stored messages again: what a rule written today makes of the
// messages its device sent before it, and what this version's reading makes
// of messages an older one stored. A message keeps its raw text, so reading
// it again after a rule has changed or gone undoes what the rule did.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/search"
	"SyslogStudio/internal/sources"
	"SyslogStudio/internal/storage"
)

// rereadBatch is how many stored messages are read at a time.
const rereadBatch = 2000

// rereadEvery is how often the progress is told while it runs.
const rereadEvery = 250 * time.Millisecond

// rereading is the one reading again an engine runs at a time.
type rereading struct {
	mu       sync.Mutex
	progress models.HistoryReread
	cancel   context.CancelFunc
	done     chan struct{}
}

// RereadHistory starts reading the stored messages opts names again, and
// returns at once: GetHistoryReread and the history:reread event follow it.
func (e *Engine) RereadHistory(opts models.RereadOptions) error {
	if e.logStore == nil || e.IsEncryptionLocked() {
		return storage.ErrNotOpen
	}
	reader := e.reader
	if opts.Rules != nil || reader == nil {
		reader = sources.New()
		// A rule that does not compile is left out, as when it is applied
		// to what arrives.
		_ = reader.SetRules(opts.Rules)
		if lookup := e.macLookup(); lookup != nil {
			reader.SetMACLookup(lookup)
		}
	}
	var since time.Time
	if opts.Since != "" {
		t, err := time.Parse(time.RFC3339, opts.Since)
		if err != nil {
			return fmt.Errorf("since: %w", err)
		}
		since = t
	}
	var addrs []search.Address
	for _, s := range opts.Sources {
		if strings.TrimSpace(s) == "" {
			continue
		}
		if err := search.CheckAddressEntry(s); err != nil {
			return err
		}
		addrs = append(addrs, search.CompileAddress(s, false))
	}

	r := &e.rereading
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.progress.Running {
		return errors.New("stored messages are being read again already")
	}
	count, last, err := e.logStore.Extent()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.progress = models.HistoryReread{Running: true, Total: count}
	r.cancel = cancel
	r.done = make(chan struct{})
	go e.reread(ctx, r.done, reader, since, addrs, last)
	e.emitter.Emit("history:reread", r.progress)
	return nil
}

// GetHistoryReread says how the reading again goes, or how the last went.
func (e *Engine) GetHistoryReread() models.HistoryReread {
	e.rereading.mu.Lock()
	defer e.rereading.mu.Unlock()
	return e.rereading.progress
}

// CancelHistoryReread stops it after the batch it is on: what was rewritten
// stays rewritten.
func (e *Engine) CancelHistoryReread() {
	e.rereading.mu.Lock()
	defer e.rereading.mu.Unlock()
	if e.rereading.cancel != nil {
		e.rereading.cancel()
	}
}

// stopReread cancels a reading again and waits for it: the database is about
// to close.
func (e *Engine) stopReread() {
	e.rereading.mu.Lock()
	cancel, done := e.rereading.cancel, e.rereading.done
	e.rereading.mu.Unlock()
	if cancel != nil {
		cancel()
		<-done
	}
}

func (e *Engine) reread(ctx context.Context, done chan struct{}, reader *sources.Reader, since time.Time, addrs []search.Address, last int64) {
	defer close(done)
	var read, changed int64
	var failure string
	told := time.Now()
	after := int64(0)
	for ctx.Err() == nil {
		msgs, next, err := e.logStore.MessagesUpTo(after, last, rereadBatch)
		if err != nil {
			failure = err.Error()
			break
		}
		if len(msgs) == 0 {
			break
		}
		after = next
		var rewrite []models.SyslogMessage
		for _, old := range msgs {
			if !fromDevice(old.Protocol) || old.ReceivedAt.Before(since) || !search.MatchAddresses(addrs, old.SourceIP) {
				continue
			}
			m := reader.ReadAt([]byte(old.RawMessage), old.SourceIP, old.Protocol, old.ReceivedAt)
			m.ID = old.ID
			if readDifferently(old, m) {
				rewrite = append(rewrite, m)
			}
		}
		if len(rewrite) > 0 {
			n, err := e.logStore.RewriteReadings(rewrite)
			changed += int64(n)
			if err != nil {
				failure = err.Error()
				break
			}
		}
		read += int64(len(msgs))
		if time.Since(told) >= rereadEvery {
			told = time.Now()
			e.rereadTell(func(p *models.HistoryReread) { p.Read, p.Changed = read, changed })
		}
	}
	cancelled := ctx.Err() != nil
	e.rereadTell(func(p *models.HistoryReread) {
		p.Running, p.Read, p.Changed, p.Error, p.Cancelled = false, read, changed, failure, cancelled
	})
	e.rereading.mu.Lock()
	e.rereading.cancel = nil
	e.rereading.mu.Unlock()
}

// rereadTell updates the progress and says it.
func (e *Engine) rereadTell(update func(*models.HistoryReread)) {
	e.rereading.mu.Lock()
	update(&e.rereading.progress)
	p := e.rereading.progress
	e.rereading.mu.Unlock()
	e.emitter.Emit("history:reread", p)
}

// fromDevice is whether a message was received from a device: an imported
// line was read by its file's format, an internal one by nobody.
func fromDevice(protocol string) bool {
	switch strings.ToUpper(protocol) {
	case "UDP", "TCP", "TLS":
		return true
	}
	return false
}

// readDifferently is whether a reading again changed what is stored of a
// message.
func readDifferently(a, b models.SyslogMessage) bool {
	return !a.Timestamp.Equal(b.Timestamp) || a.Severity != b.Severity || a.Facility != b.Facility ||
		a.Hostname != b.Hostname || a.AppName != b.AppName || a.ProcID != b.ProcID || a.MsgID != b.MsgID ||
		a.Message != b.Message || a.Version != b.Version || a.StructuredData != b.StructuredData
}
