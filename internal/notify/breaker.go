package notify

import (
	"fmt"
	"hash/fnv"
	"sort"
	"sync"
	"time"
)

// The fingerprint guard cuts a loop whose messages come back unchanged. A
// collector that rewrites the timestamp on receipt — many do — breaks that
// match, and the echo then looks like a brand new message. Nothing downstream
// can tell the difference, so the relay runs until something gives out.
//
// This is the backstop for that case. It does not try to identify individual
// looped messages; it watches what a destination is being asked to carry and
// stops the destination when the traffic stops looking like logs.
//
// A rate ceiling alone is not good enough to act on. A device rebooting and
// flushing its buffer, or a debug level left on overnight, produces a genuine
// burst that no operator wants silently cut off. So the breaker asks for a
// second, structural signal before it trips at the ordinary ceiling:
//
//	repeats — the share of messages bound for this destination that are
//	          textually identical to one seen recently, ignoring timestamps.
//
// In a loop this approaches one, because the same lines circulate whatever
// gets rewritten in transit. In a genuine burst it stays low, because a device
// dumping its buffer emits varied lines. Only a flood that is BOTH fast and
// almost entirely repetition trips the ordinary ceiling.
//
// Above a multiple of the ceiling the rate alone is enough: at that point the
// destination cannot keep up regardless of the cause, and continuing to queue
// for it helps nobody.

const (
	// breakerWindow is the period the rate is averaged over. Long on purpose:
	// a burst is over in seconds, a loop is not, and averaging over half a
	// minute is what separates them.
	breakerWindow = 30 * time.Second
	// breakerBuckets divides the window for the rolling count.
	breakerBuckets = 30
	// defaultMaxRate is the per-destination ceiling in messages per second
	// when a sink does not set its own. Sustained for the whole window this is
	// 60 000 messages to ONE destination — far above alerting, and above the
	// steady rate of any relay that has not gone wrong.
	defaultMaxRate = 2000
	// runawayMultiple is how far past the ceiling the rate alone trips,
	// without the repetition signal.
	runawayMultiple = 5
	// repeatRatioToTrip is the share of repeated content that turns a fast
	// stream into a suspected loop.
	repeatRatioToTrip = 0.9
	// minSamplesToTrip stops a handful of messages from tripping anything: a
	// ratio over three messages means nothing.
	minSamplesToTrip = 200
	// minSecondsToTrip is how long traffic must have been observed before any
	// judgement is made, so a single crowded second cannot cut a destination.
	minSecondsToTrip = 5
	// minSecondsForRunaway is the longer span the rate-only rule needs. A
	// burst is over well within this; a loop is not.
	minSecondsForRunaway = 15
	// weakGuardEntries bounds the memory used to recognise repeated content.
	weakGuardEntries = 20000
)

// weakFingerprint identifies a message by content that survives a relay even
// when the timestamp does not: who sent it, from what program, and what it
// said. Deliberately weaker than fingerprint() — this one is never used to
// drop a message, only to measure how repetitive a stream is.
func weakFingerprint(host, app, message string) uint64 {
	h := fnv.New64a()
	for _, s := range []string{host, app, message} {
		h.Write([]byte(s))
		h.Write([]byte{0x1f})
	}
	return h.Sum64()
}

// TripReason says why a destination was cut off, so the operator is told which
// of the two situations they are in.
type TripReason string

const (
	// TripLoop is a fast stream that is almost entirely repetition.
	TripLoop TripReason = "loop"
	// TripRunaway is a rate so far past the ceiling that the cause does not
	// matter.
	TripRunaway TripReason = "runaway"
)

// bucket is one slice of the rolling window.
type bucket struct {
	second  int64
	total   int
	repeats int
}

// sinkMeter measures one destination's recent traffic.
//
// Fixed buckets stamped with their second rather than a list of timestamps:
// the cost per message is a modulo and two increments, which matters because
// this runs on the receive path.
type sinkMeter struct {
	buckets [breakerBuckets]bucket
}

func (m *sinkMeter) add(now time.Time, repeat bool) {
	sec := now.Unix()
	b := &m.buckets[sec%breakerBuckets]
	if b.second != sec {
		// This slot belongs to an older revolution of the window; reuse it.
		b.second = sec
		b.total = 0
		b.repeats = 0
	}
	b.total++
	if repeat {
		b.repeats++
	}
}

// totals sums the window, ignoring buckets that have aged out, and reports how
// many seconds it actually covers.
//
// The elapsed span matters: dividing by the full window would understate a
// loop that has only been running five seconds, and waiting thirty seconds to
// notice means several hundred thousand messages already relayed.
func (m *sinkMeter) totals(now time.Time) (total, repeats int, elapsed int64) {
	cutoff := now.Unix() - int64(breakerBuckets) + 1
	oldest := now.Unix()
	for i := range m.buckets {
		b := &m.buckets[i]
		if b.second < cutoff || b.total == 0 {
			continue
		}
		total += b.total
		repeats += b.repeats
		if b.second < oldest {
			oldest = b.second
		}
	}
	return total, repeats, now.Unix() - oldest + 1
}

// breaker decides when a destination has to be cut off.
type breaker struct {
	mu      sync.Mutex
	meters  map[string]*sinkMeter
	tripped map[string]TripReason
	weak    *loopGuard
}

func newBreaker() *breaker {
	return &breaker{
		meters:  make(map[string]*sinkMeter),
		tripped: make(map[string]TripReason),
		// A window rather than a fixed size, so content is judged repetitive
		// against what was recently seen, not against all history.
		weak: newLoopGuard(breakerWindow, weakGuardEntries),
	}
}

// maxRateFor resolves a sink's ceiling: 0 takes the default, a negative value
// means the operator has turned the breaker off for that destination.
func maxRateFor(cfg SinkConfig) int {
	switch {
	case cfg.MaxRate < 0:
		return 0 // no ceiling
	case cfg.MaxRate == 0:
		return defaultMaxRate
	default:
		return cfg.MaxRate
	}
}

// isTripped reports whether a destination is currently cut off.
func (b *breaker) isTripped(sinkID string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, ok := b.tripped[sinkID]
	return ok
}

// record accounts for one message bound for a destination.
//
// blocked says the destination must not be sent to. justTripped is set only on
// the transition, so the operator gets one log entry and one notification
// rather than one per message for as long as the flood lasts.
func (b *breaker) record(cfg SinkConfig, host, app, message string, now time.Time) (blocked bool, justTripped TripReason) {
	limit := maxRateFor(cfg)
	if limit <= 0 {
		return false, ""
	}

	repeat := b.weak.seen(weakFingerprint(host, app, message), now)

	b.mu.Lock()
	defer b.mu.Unlock()
	if _, already := b.tripped[cfg.ID]; already {
		return true, ""
	}

	m := b.meters[cfg.ID]
	if m == nil {
		m = &sinkMeter{}
		b.meters[cfg.ID] = m
	}
	m.add(now, repeat)

	total, repeats, elapsed := m.totals(now)
	if total < minSamplesToTrip || elapsed < minSecondsToTrip {
		return false, ""
	}

	rate := float64(total) / float64(elapsed)
	ceiling := float64(limit)

	// Repetition first, because it is the signal that tells a loop from a
	// device emptying its buffer, and it is safe to act on early.
	if rate > ceiling && float64(repeats)/float64(total) >= repeatRatioToTrip {
		b.tripped[cfg.ID] = TripLoop
		return true, TripLoop
	}

	// Rate alone needs to have held for much longer before it counts. A
	// restarting device can push tens of thousands of varied lines in a few
	// seconds; nothing legitimate keeps that up for half the window.
	if elapsed >= minSecondsForRunaway && rate > ceiling*runawayMultiple {
		b.tripped[cfg.ID] = TripRunaway
		return true, TripRunaway
	}
	return false, ""
}

// reset clears a destination's trip and its history, so re-enabling it in the
// UI actually gives it a fresh start rather than tripping again on the counts
// that cut it off.
func (b *breaker) reset(sinkID string) {
	b.mu.Lock()
	delete(b.tripped, sinkID)
	delete(b.meters, sinkID)
	b.mu.Unlock()
}

// forget drops destinations that no longer exist.
func (b *breaker) forget(keep map[string]bool) {
	b.mu.Lock()
	for id := range b.meters {
		if !keep[id] {
			delete(b.meters, id)
		}
	}
	for id := range b.tripped {
		if !keep[id] {
			delete(b.tripped, id)
		}
	}
	b.mu.Unlock()
}

// trippedIDs lists the destinations currently cut off, so the UI can name them
// rather than only report that something is wrong.
func (b *breaker) trippedIDs() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.tripped) == 0 {
		return nil
	}
	out := make([]string, 0, len(b.tripped))
	for id := range b.tripped {
		out = append(out, id)
	}
	sort.Strings(out) // stable, so the UI does not reshuffle between polls
	return out
}

// describeTarget names where a destination sends, for a log line the operator
// reads. Built from the configuration rather than a live sink, because a
// destination can be cut off before one was ever constructed.
func describeTarget(cfg SinkConfig) string {
	switch cfg.Kind {
	case SinkSyslog:
		return fmt.Sprintf("syslog %s://%s", cfg.Syslog.Protocol, cfg.Syslog.Address)
	case SinkWebhook:
		return "webhook " + cfg.Webhook.URL
	case SinkEmail:
		return fmt.Sprintf("email %s:%d", cfg.Email.Host, cfg.Email.Port)
	default:
		return cfg.Kind
	}
}
