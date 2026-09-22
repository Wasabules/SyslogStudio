package notify

import (
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"SyslogStudio/internal/models"
)

const (
	// queueCapacity bounds the pending-delivery queue. The dispatcher sits on
	// the message hot path, which can run at tens of thousands per second, so
	// an unbounded queue is an out-of-memory abort waiting for a slow SMTP
	// server. Overflow is counted and reported rather than silently absorbed.
	queueCapacity = 4096
	// workers deliver in parallel. One sink being slow must not stall the rest,
	// and a handful is enough: these are network-bound, not CPU-bound.
	workers = 4
	// maxAttempts is how many times one message is tried before it is dropped.
	maxAttempts = 3
	// baseRetryDelay is the first backoff step; it doubles per attempt.
	baseRetryDelay = 2 * time.Second
	// maxLogEntries bounds the in-memory delivery log.
	maxLogEntries = 500
)

// DeliveryEntry is one line of the delivery log.
type DeliveryEntry struct {
	Time     time.Time `json:"time"`
	SinkID   string    `json:"sinkId"`
	SinkName string    `json:"sinkName"`
	Target   string    `json:"target"`
	OK       bool      `json:"ok"`
	Attempts int       `json:"attempts"`
	Error    string    `json:"error,omitempty"`
	Subject  string    `json:"subject,omitempty"`
}

// Stats summarises dispatcher activity.
type Stats struct {
	Matched   int64 `json:"matched"`
	Delivered int64 `json:"delivered"`
	Failed    int64 `json:"failed"`
	// Dropped counts messages discarded because the queue was full. Non-zero
	// means deliveries were lost, which is why it is reported rather than only
	// logged.
	Dropped int64 `json:"dropped"`
	Queued  int   `json:"queued"`
}

// Emitter is the subset of the event bus the dispatcher needs.
type Emitter interface {
	Emit(name string, data ...interface{})
}

// job is one rendered message bound for one sink.
type job struct {
	sinkID   string
	sinkName string
	rendered Rendered
	attempt  int
}

// Dispatcher routes messages to sinks.
//
// Enqueue runs on the message hot path and must never block: it renders, drops
// the job on a bounded queue, and returns. Everything slow — dialling, TLS,
// SMTP, retries — happens on the workers.
type Dispatcher struct {
	emitter Emitter

	mu       sync.RWMutex
	routes   []compiledRoute
	sinkCfgs map[string]SinkConfig
	live     map[string]Sink
	secrets  func(sinkID string) string

	queue chan job
	stop  chan struct{}
	wg    sync.WaitGroup
	once  sync.Once

	matched   atomic.Int64
	delivered atomic.Int64
	failed    atomic.Int64
	dropped   atomic.Int64

	logMu  sync.Mutex
	logBuf []DeliveryEntry
}

// NewDispatcher creates a dispatcher. secrets resolves a sink's credential by
// id, so the dispatcher never holds one in its own configuration.
func NewDispatcher(emitter Emitter, secrets func(sinkID string) string) *Dispatcher {
	d := &Dispatcher{
		emitter:  emitter,
		sinkCfgs: make(map[string]SinkConfig),
		live:     make(map[string]Sink),
		secrets:  secrets,
		queue:    make(chan job, queueCapacity),
		stop:     make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		d.wg.Add(1)
		go d.worker()
	}
	return d
}

// Configure replaces the routing table and destination set.
//
// Live sinks whose configuration changed are closed, so the next delivery
// rebuilds them: a sink left holding a connection to the previous address would
// keep sending to it.
func (d *Dispatcher) Configure(routes []Route, sinks []SinkConfig) {
	compiled := compileRoutes(routes)

	next := make(map[string]SinkConfig, len(sinks))
	for _, s := range sinks {
		next[s.ID] = s
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	for id, live := range d.live {
		old, hadOld := d.sinkCfgs[id]
		cur, stillThere := next[id]
		if !stillThere || !sameSinkConfig(old, cur) || !hadOld {
			live.Close()
			delete(d.live, id)
		}
	}
	d.routes = compiled
	d.sinkCfgs = next
}

// sameSinkConfig reports whether a live sink can be kept. Compared on the
// fields that define the connection and the payload; the name is cosmetic.
func sameSinkConfig(a, b SinkConfig) bool {
	if a.Kind != b.Kind || a.Enabled != b.Enabled || a.Redact != b.Redact {
		return false
	}
	da, okA := Destination(a)
	db, okB := Destination(b)
	if !okA || !okB || da != db {
		return false
	}
	return a.Syslog == b.Syslog && a.Email.equal(b.Email) &&
		a.Webhook.equal(b.Webhook) && a.Template == b.Template
}

func (c EmailSinkConfig) equal(o EmailSinkConfig) bool {
	if c.Host != o.Host || c.Port != o.Port || c.Username != o.Username ||
		c.From != o.From || c.Encryption != o.Encryption ||
		c.Format != o.Format || c.Timeout != o.Timeout || len(c.To) != len(o.To) {
		return false
	}
	for i := range c.To {
		if c.To[i] != o.To[i] {
			return false
		}
	}
	return true
}

func (c WebhookSinkConfig) equal(o WebhookSinkConfig) bool {
	if c.URL != o.URL || c.Method != o.Method || c.Timeout != o.Timeout ||
		c.PayloadMode != o.PayloadMode || len(c.Headers) != len(o.Headers) {
		return false
	}
	for k, v := range c.Headers {
		if o.Headers[k] != v {
			return false
		}
	}
	return true
}

// Dispatch routes one message. Called on the hot path; never blocks.
func (d *Dispatcher) Dispatch(msg models.SyslogMessage) {
	d.mu.RLock()
	routes := d.routes
	d.mu.RUnlock()
	if len(routes) == 0 {
		return
	}

	ids := selectSinks(routes, msg, time.Now())
	if len(ids) == 0 {
		return
	}
	d.matched.Add(1)

	for _, id := range ids {
		d.mu.RLock()
		cfg, ok := d.sinkCfgs[id]
		d.mu.RUnlock()
		if !ok || !cfg.Enabled {
			continue
		}

		// Rendered here, on the hot path, on purpose: every retry then sends
		// byte-identical content, and a worker never has to reach back into a
		// message store that may have rotated the entry away.
		j := job{
			sinkID:   id,
			sinkName: cfg.Name,
			rendered: Render(msg, DefaultedTemplate(cfg.Kind, cfg.Template), cfg.Redact),
		}
		select {
		case d.queue <- j:
		default:
			d.dropped.Add(1)
		}
	}
}

func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for {
		select {
		case <-d.stop:
			return
		case j := <-d.queue:
			d.deliver(j)
		}
	}
}

func (d *Dispatcher) deliver(j job) {
	sink, target, err := d.sinkFor(j.sinkID)
	if err != nil {
		d.record(j, target, err)
		return
	}

	err = sink.Send(j.rendered)
	if err == nil {
		d.delivered.Add(1)
		d.record(j, target, nil)
		return
	}

	// A failed send may have left a dead connection behind; drop the live sink
	// so the next attempt rebuilds it.
	d.mu.Lock()
	if live, ok := d.live[j.sinkID]; ok && live == sink {
		live.Close()
		delete(d.live, j.sinkID)
	}
	d.mu.Unlock()

	j.attempt++
	if j.attempt >= maxAttempts {
		d.failed.Add(1)
		d.record(j, target, err)
		return
	}

	// Requeue after a backoff, on a timer rather than by sleeping here: a
	// worker asleep is a worker not delivering for every other sink.
	delay := baseRetryDelay << (j.attempt - 1)
	time.AfterFunc(delay, func() {
		select {
		case <-d.stop:
		case d.queue <- j:
		default:
			d.dropped.Add(1)
		}
	})
}

// sinkFor returns the live sink for an id, building it on first use.
func (d *Dispatcher) sinkFor(id string) (Sink, string, error) {
	d.mu.RLock()
	live, ok := d.live[id]
	cfg, known := d.sinkCfgs[id]
	d.mu.RUnlock()
	if ok {
		return live, live.Describe(), nil
	}
	if !known {
		return nil, "", errf("destination %s no longer exists", id)
	}

	secret := ""
	if d.secrets != nil {
		secret = d.secrets(id)
	}
	built, err := Build(cfg, secret)
	if err != nil {
		return nil, cfg.Name, scrubSecret(err, secret)
	}

	d.mu.Lock()
	// Another worker may have built it while this one was dialling; keep theirs
	// so there is one connection per sink rather than one per worker.
	if existing, raced := d.live[id]; raced {
		d.mu.Unlock()
		built.Close()
		return existing, existing.Describe(), nil
	}
	d.live[id] = built
	d.mu.Unlock()
	return built, built.Describe(), nil
}

func (d *Dispatcher) record(j job, target string, err error) {
	entry := DeliveryEntry{
		Time:     time.Now(),
		SinkID:   j.sinkID,
		SinkName: j.sinkName,
		Target:   target,
		OK:       err == nil,
		Attempts: j.attempt + 1,
		Subject:  j.rendered.Subject,
	}
	if err != nil {
		entry.Error = err.Error()
		slog.Warn("notify delivery failed", "sink", j.sinkName, "target", target,
			"attempts", entry.Attempts, "error", err)
	}

	d.logMu.Lock()
	d.logBuf = append(d.logBuf, entry)
	if len(d.logBuf) > maxLogEntries {
		d.logBuf = d.logBuf[len(d.logBuf)-maxLogEntries:]
	}
	d.logMu.Unlock()

	if d.emitter != nil {
		d.emitter.Emit("syslog:delivery", entry)
	}
}

// Log returns the delivery log, newest last.
func (d *Dispatcher) Log() []DeliveryEntry {
	d.logMu.Lock()
	defer d.logMu.Unlock()
	out := make([]DeliveryEntry, len(d.logBuf))
	copy(out, d.logBuf)
	return out
}

// ClearLog empties the delivery log.
func (d *Dispatcher) ClearLog() {
	d.logMu.Lock()
	d.logBuf = nil
	d.logMu.Unlock()
}

// Stats returns counters.
func (d *Dispatcher) Stats() Stats {
	return Stats{
		Matched:   d.matched.Load(),
		Delivered: d.delivered.Load(),
		Failed:    d.failed.Load(),
		Dropped:   d.dropped.Load(),
		Queued:    len(d.queue),
	}
}

// TestSink delivers one message to a sink immediately, bypassing routing and
// the queue, so the UI's "send test" button reports a real result rather than
// queueing something the operator then has to go and look for.
//
// cfg is the configuration as edited, which may not be saved yet. secret is
// resolved by the caller, which is where the destination-binding rule is
// enforced — a caller must not hand over a stored credential for a destination
// it was not stored against.
func TestSink(cfg SinkConfig, secret string, msg models.SyslogMessage) error {
	sink, err := Build(cfg, secret)
	if err != nil {
		return scrubSecret(err, secret)
	}
	defer sink.Close()
	return scrubSecret(sink.Send(Render(msg, DefaultedTemplate(cfg.Kind, cfg.Template), cfg.Redact)), secret)
}

// Close stops the workers and releases every connection.
func (d *Dispatcher) Close() {
	d.once.Do(func() {
		close(d.stop)
		d.wg.Wait()
		d.mu.Lock()
		for id, s := range d.live {
			s.Close()
			delete(d.live, id)
		}
		d.mu.Unlock()
	})
}
