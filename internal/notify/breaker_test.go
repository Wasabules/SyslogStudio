package notify

import (
	"fmt"
	"testing"
	"time"
)

// The breaker is only worth having if it tells a loop from a busy night. These
// tests are mostly about the second half: the traffic that must NOT trip it.

func relaySink(id string, maxRate int) SinkConfig {
	return SinkConfig{
		ID: id, Name: id, Kind: SinkSyslog, Enabled: true, MaxRate: maxRate,
		Syslog: SyslogSinkConfig{Address: "10.0.0.9:514", Protocol: "udp", Facility: 16},
	}
}

// feed pushes n messages per second for the given number of seconds and
// returns the reason it tripped, or "" if it never did.
func feed(b *breaker, cfg SinkConfig, start time.Time, perSecond, seconds int, text func(i int) string) TripReason {
	n := 0
	for s := 0; s < seconds; s++ {
		at := start.Add(time.Duration(s) * time.Second)
		for i := 0; i < perSecond; i++ {
			_, reason := b.record(cfg, "router-7", "sshd", text(n), at)
			n++
			if reason != "" {
				return reason
			}
		}
	}
	return ""
}

func TestBreaker_CutsARepetitiveFlood(t *testing.T) {
	b := newBreaker()
	// The shape of a loop: fast, and the same handful of lines going round.
	got := feed(b, relaySink("s1", 100), time.Now(), 500, 20,
		func(i int) string { return fmt.Sprintf("circulating line %d", i%5) })
	if got != TripLoop {
		t.Fatalf("reason = %q, want %q", got, TripLoop)
	}
	if !b.isTripped("s1") {
		t.Error("the destination was not recorded as cut off")
	}
}

// The case that makes a naive breaker useless: a device rebooting and emptying
// its buffer. Fast, but every line is different.
func TestBreaker_LetsAGenuineBurstThrough(t *testing.T) {
	b := newBreaker()
	got := feed(b, relaySink("s1", 100), time.Now(), 5000, 5,
		func(i int) string { return fmt.Sprintf("unique event %d payload=%x", i, i*2654435761) })
	if got != "" {
		t.Fatalf("a burst of varied lines tripped the breaker as %q", got)
	}
	if b.isTripped("s1") {
		t.Error("the destination was cut off by a legitimate burst")
	}
}

// Sustained far above the ceiling trips even when the content is varied,
// because at that point the destination cannot keep up whatever the cause.
func TestBreaker_CutsASustainedRunaway(t *testing.T) {
	b := newBreaker()
	got := feed(b, relaySink("s1", 100), time.Now(), 5000, 20,
		func(i int) string { return fmt.Sprintf("unique event %d payload=%x", i, i*2654435761) })
	if got != TripRunaway {
		t.Fatalf("reason = %q, want %q", got, TripRunaway)
	}
}

// A device repeating one line is repetitive but slow. Cutting it off would
// lose logs for no reason.
func TestBreaker_IgnoresSlowRepetition(t *testing.T) {
	b := newBreaker()
	got := feed(b, relaySink("s1", 100), time.Now(), 20, 30,
		func(int) string { return "link down on eth0" })
	if got != "" {
		t.Fatalf("slow repetition tripped the breaker as %q", got)
	}
}

// A brief spike is not evidence of anything.
func TestBreaker_NeedsTimeBeforeJudging(t *testing.T) {
	b := newBreaker()
	got := feed(b, relaySink("s1", 100), time.Now(), 10000, 2,
		func(i int) string { return fmt.Sprintf("line %d", i%3) })
	if got != "" {
		t.Fatalf("two seconds of traffic tripped the breaker as %q", got)
	}
}

func TestBreaker_HonoursPerSinkLimits(t *testing.T) {
	loop := func(i int) string { return fmt.Sprintf("line %d", i%4) }

	// A generous limit tolerates what a tight one refuses.
	tight := newBreaker()
	if got := feed(tight, relaySink("s1", 100), time.Now(), 400, 20, loop); got == "" {
		t.Error("400/s did not trip a 100/s ceiling")
	}
	loose := newBreaker()
	if got := feed(loose, relaySink("s1", 5000), time.Now(), 400, 20, loop); got != "" {
		t.Errorf("400/s tripped a 5000/s ceiling as %q", got)
	}

	// A negative limit turns the breaker off for that destination.
	off := newBreaker()
	if got := feed(off, relaySink("s1", -1), time.Now(), 50000, 30, loop); got != "" {
		t.Errorf("a destination with the breaker disabled still tripped as %q", got)
	}
}

func TestMaxRateFor(t *testing.T) {
	cases := []struct {
		set  int
		want int
	}{
		{0, defaultMaxRate}, // unset takes the default
		{750, 750},          // an explicit ceiling is used as given
		{-1, 0},             // negative means no ceiling at all
	}
	for _, c := range cases {
		if got := maxRateFor(SinkConfig{MaxRate: c.set}); got != c.want {
			t.Errorf("maxRateFor(%d) = %d, want %d", c.set, got, c.want)
		}
	}
}

// Once cut off, a destination stays cut off — but only reports the transition
// once, so the operator gets one notification rather than one per message.
func TestBreaker_ReportsTheTransitionOnce(t *testing.T) {
	b := newBreaker()
	cfg := relaySink("s1", 100)
	start := time.Now()

	if got := feed(b, cfg, start, 500, 20, func(i int) string { return fmt.Sprintf("line %d", i%5) }); got == "" {
		t.Fatal("never tripped")
	}

	later := start.Add(25 * time.Second)
	for i := 0; i < 100; i++ {
		blocked, reason := b.record(cfg, "router-7", "sshd", "line 1", later)
		if !blocked {
			t.Fatal("a message was let through to a destination that is cut off")
		}
		if reason != "" {
			t.Fatalf("the trip was reported again on message %d", i)
		}
	}
}

func TestBreaker_ResetGivesAFreshStart(t *testing.T) {
	b := newBreaker()
	cfg := relaySink("s1", 100)
	if got := feed(b, cfg, time.Now(), 500, 20, func(i int) string { return fmt.Sprintf("line %d", i%5) }); got == "" {
		t.Fatal("never tripped")
	}

	b.reset("s1")
	if b.isTripped("s1") {
		t.Fatal("still cut off after a reset")
	}
	// And the counts that tripped it are gone, so it is not cut off again on
	// the next message.
	if blocked, _ := b.record(cfg, "router-7", "sshd", "line 1", time.Now()); blocked {
		t.Fatal("tripped again immediately on the counts that had been cleared")
	}
}

func TestBreaker_ForgetsRemovedDestinations(t *testing.T) {
	b := newBreaker()
	cfg := relaySink("s1", 100)
	if got := feed(b, cfg, time.Now(), 500, 20, func(i int) string { return fmt.Sprintf("line %d", i%5) }); got == "" {
		t.Fatal("never tripped")
	}
	b.forget(map[string]bool{"other": true})
	if b.isTripped("s1") {
		t.Error("a deleted destination is still held as cut off")
	}
	if len(b.trippedIDs()) != 0 {
		t.Errorf("trippedIDs = %v, want empty", b.trippedIDs())
	}
}

func TestSinkMeter_WindowAgesOut(t *testing.T) {
	var m sinkMeter
	start := time.Unix(1_700_000_000, 0)
	for i := 0; i < 10; i++ {
		m.add(start, false)
	}
	total, _, elapsed := m.totals(start)
	if total != 10 || elapsed != 1 {
		t.Fatalf("total=%d elapsed=%d, want 10 and 1", total, elapsed)
	}

	// Well past the window, nothing of it remains.
	later := start.Add(breakerWindow + 5*time.Second)
	if total, _, _ := m.totals(later); total != 0 {
		t.Errorf("total = %d after the window, want 0", total)
	}
}

func TestWeakFingerprint_IgnoresTimeButNotContent(t *testing.T) {
	// The whole point of having two fingerprints: a collector that rewrites the
	// timestamp defeats the strong one, which is why the breaker uses a weak
	// one that never looked at the time to begin with.
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	early := messageFields{timestamp: t0, hostname: "h", appName: "a", message: "same"}
	rewritten := messageFields{timestamp: t0.Add(time.Minute), hostname: "h", appName: "a", message: "same"}
	if fingerprint(early) == fingerprint(rewritten) {
		t.Error("the strong fingerprint should notice a rewritten timestamp")
	}
	if weakFingerprint(early.hostname, early.appName, early.message) !=
		weakFingerprint(rewritten.hostname, rewritten.appName, rewritten.message) {
		t.Error("the weak fingerprint must survive a rewritten timestamp")
	}
	if weakFingerprint("h", "a", "one") == weakFingerprint("h", "a", "two") {
		t.Error("different text collides")
	}
	if weakFingerprint("h1", "a", "x") == weakFingerprint("h2", "a", "x") {
		t.Error("different hosts collide")
	}
	if weakFingerprint("ab", "c", "") == weakFingerprint("a", "bc", "") {
		t.Error("field boundaries are not separated")
	}
}

func TestDescribeTarget(t *testing.T) {
	cases := map[string]SinkConfig{
		"syslog udp://10.0.0.9:514": relaySink("s", 0),
		"webhook https://h/x": {Kind: SinkWebhook,
			Webhook: WebhookSinkConfig{URL: "https://h/x"}},
		"email smtp.example.com:587": {Kind: SinkEmail,
			Email: EmailSinkConfig{Host: "smtp.example.com", Port: 587}},
	}
	for want, cfg := range cases {
		if got := describeTarget(cfg); got != want {
			t.Errorf("describeTarget = %q, want %q", got, want)
		}
	}
}
