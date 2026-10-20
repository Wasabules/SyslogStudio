package inbox

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"SyslogStudio/internal/models"
)

// When a batch is sealed: after this long, or once it holds this many
// messages or bytes, whichever comes first. Each batch carries about a
// kilobyte of key material, so the interval is longer while no window is
// there to collect: fewer, larger batches.
const (
	collectedInterval = 5 * time.Second
	idleInterval      = 30 * time.Second
	maxBatchMessages  = 2000
	maxBatchBytes     = 1 << 20
	// maxPending bounds what waits in memory to be sealed, if sealing or the
	// disk cannot keep up.
	maxPending = 50000
	// collectorGone is how long after a window last asked for the batches
	// it is taken to be gone.
	collectorGone = time.Minute
)

// Writer seals what a service receives into its inbox. Add never waits:
// sealing and writing happen on the writer's own goroutine, not on the
// receiver's.
type Writer struct {
	box   Box
	pub   []byte
	keyID string
	quota int64
	log   *slog.Logger
	// onBatch is told each time a batch is written, so the windows can come
	// and collect it.
	onBatch func()

	mu      sync.Mutex
	pending []models.SyslogMessage
	size    int
	bytes   int64
	batches int
	dropped int64
	lastErr string
	full    bool
	filling bool
	// collected is when a window last asked what waits.
	collected time.Time
	seq       int

	kick chan struct{}
	stop chan struct{}
	done chan struct{}
}

// NewWriter seals for cfg's public key into dir, and counts what already
// waits there against the quota.
func NewWriter(dir string, cfg models.InboxConfig, log *slog.Logger, onBatch func()) (*Writer, error) {
	if err := CheckPublicKey(cfg.PublicKey); err != nil {
		return nil, err
	}
	if log == nil {
		log = slog.Default()
	}
	w := &Writer{
		box:     Box{Dir: dir},
		pub:     cfg.PublicKey,
		keyID:   KeyID(cfg.PublicKey),
		quota:   cfg.Quota(),
		log:     log,
		onBatch: onBatch,
		kick:    make(chan struct{}, 1),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	waiting, err := w.box.List()
	if err != nil {
		return nil, fmt.Errorf("read the inbox: %w", err)
	}
	for _, b := range waiting {
		w.bytes += b.Bytes
		w.batches++
	}
	go w.loop()
	return w, nil
}

// Add queues a message to be sealed.
func (w *Writer) Add(msg models.SyslogMessage) {
	w.mu.Lock()
	if len(w.pending) >= maxPending {
		w.dropped++
		w.mu.Unlock()
		return
	}
	w.pending = append(w.pending, msg)
	w.size += approxSize(msg)
	ready := len(w.pending) >= maxBatchMessages || w.size >= maxBatchBytes
	w.mu.Unlock()
	if ready {
		select {
		case w.kick <- struct{}{}:
		default:
		}
	}
}

// MarkCollected records that a window asked what waits: while one keeps
// asking, batches are sealed sooner, so its history keeps up.
func (w *Writer) MarkCollected() {
	w.mu.Lock()
	was := w.collectingLocked()
	w.collected = time.Now()
	w.mu.Unlock()
	if !was {
		select {
		case w.kick <- struct{}{}:
		default:
		}
	}
}

func (w *Writer) collectingLocked() bool {
	return !w.collected.IsZero() && time.Since(w.collected) < collectorGone
}

func approxSize(m models.SyslogMessage) int {
	return 256 + len(m.Message) + len(m.RawMessage) + len(m.StructuredData) + len(m.Hostname) + len(m.AppName)
}

func (w *Writer) loop() {
	defer close(w.done)
	for {
		w.mu.Lock()
		interval := idleInterval
		if w.collectingLocked() {
			interval = collectedInterval
		}
		w.mu.Unlock()
		t := time.NewTimer(interval)
		select {
		case <-w.stop:
			t.Stop()
			w.flush()
			return
		case <-w.kick:
			t.Stop()
		case <-t.C:
		}
		w.flush()
	}
}

// flush seals what is pending, a batch at a time.
func (w *Writer) flush() {
	for {
		w.mu.Lock()
		n := min(len(w.pending), maxBatchMessages)
		if n == 0 {
			w.mu.Unlock()
			return
		}
		batch := w.pending[:n:n]
		w.pending = w.pending[n:]
		if len(w.pending) == 0 {
			w.pending = nil
			w.size = 0
		} else {
			w.size = 0
			for _, m := range w.pending {
				w.size += approxSize(m)
			}
		}
		w.mu.Unlock()
		w.write(batch, true)
	}
}

// write seals and stores one batch. Within the quota unless told otherwise:
// moving messages that already were on disk does not add to what is kept.
func (w *Writer) write(batch []models.SyslogMessage, quota bool) error {
	data, err := Seal(w.pub, batch)
	if err != nil {
		w.fail(len(batch), fmt.Errorf("seal a batch: %w", err))
		return err
	}

	w.mu.Lock()
	if quota && w.bytes+int64(len(data)) > w.quota {
		w.dropped += int64(len(batch))
		wasFull := w.full
		w.full = true
		w.lastErr = "the inbox is full: messages are dropped until a window collects it"
		w.mu.Unlock()
		if !wasFull {
			w.log.Error("the sealed inbox is full; dropping what arrives until a window collects it",
				"quotaBytes", w.quota)
		}
		return fmt.Errorf("the inbox is full")
	}
	w.seq = (w.seq + 1) % 1_000_000
	id := fmt.Sprintf("%020d-%06d", time.Now().UnixNano(), w.seq)
	w.mu.Unlock()

	if err := w.box.write(id, data); err != nil {
		w.fail(len(batch), fmt.Errorf("write a batch: %w", err))
		return err
	}

	w.mu.Lock()
	w.bytes += int64(len(data))
	w.batches++
	w.lastErr = ""
	w.full = false
	startFilling := !w.filling && w.statusLocked().Filling()
	if startFilling {
		w.filling = true
	}
	w.mu.Unlock()
	if startFilling {
		w.log.Warn("the sealed inbox is four-fifths full; open SyslogStudio and unlock it to collect the messages",
			"bytes", w.bytesNow(), "quotaBytes", w.quota)
	}
	if w.onBatch != nil {
		w.onBatch()
	}
	return nil
}

// WriteNow seals msgs as one batch at once, outside the quota: for messages
// moved in from elsewhere, which were already being kept.
func (w *Writer) WriteNow(msgs []models.SyslogMessage) error {
	if len(msgs) == 0 {
		return nil
	}
	return w.write(msgs, false)
}

func (w *Writer) fail(n int, err error) {
	w.mu.Lock()
	w.dropped += int64(n)
	w.lastErr = err.Error()
	w.mu.Unlock()
	w.log.Error("a sealed batch was lost", "messages", n, "error", err)
}

func (w *Writer) bytesNow() int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.bytes
}

// Remove deletes a batch a window has collected.
func (w *Writer) Remove(id string) error {
	n, err := w.box.Remove(id)
	if err != nil || n == 0 {
		return err
	}
	w.mu.Lock()
	w.bytes -= n
	w.batches--
	if w.bytes < 0 || w.batches < 0 {
		w.bytes, w.batches = 0, 0
	}
	if w.filling && !w.statusLocked().Filling() {
		w.filling = false
	}
	w.mu.Unlock()
	return nil
}

// Box is the directory the writer stores into.
func (w *Writer) Box() Box { return w.box }

// Status is what the inbox holds.
func (w *Writer) Status() models.InboxStatus {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.statusLocked()
}

func (w *Writer) statusLocked() models.InboxStatus {
	return models.InboxStatus{
		Sealed:  true,
		KeyID:   w.keyID,
		Batches: w.batches,
		Bytes:   w.bytes,
		Quota:   w.quota,
		Dropped: w.dropped,
		Error:   w.lastErr,
	}
}

// Close seals what is pending and stops.
func (w *Writer) Close() {
	select {
	case <-w.stop:
	default:
		close(w.stop)
	}
	<-w.done
}
