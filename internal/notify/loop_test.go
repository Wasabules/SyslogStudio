package notify

import (
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

func fields(ts time.Time, host, app, procID, text string) messageFields {
	return messageFields{timestamp: ts, hostname: host, appName: app, procID: procID, message: text}
}

// The echo of a relayed message must fingerprint identically to the original,
// or the guard never recognises the loop it exists to cut.
func TestFingerprint_SurvivesARelayRoundTrip(t *testing.T) {
	// A message received with sub-millisecond precision. The RFC 5424 frame we
	// emit carries milliseconds, so the copy that comes back has lost the rest.
	ts := time.Date(2026, 9, 22, 10, 0, 0, 123_456_789, time.UTC)
	original := fields(ts, "router-7", "sshd", "4242", "Accepted password for alice")

	returned := fields(ts.Truncate(time.Millisecond), "router-7", "sshd", "4242", "Accepted password for alice")
	if fingerprint(original) != fingerprint(returned) {
		t.Fatal("a message does not match its own echo; loops would never be cut")
	}

	// An absent PROCID goes out as "-" and comes back as "-".
	noProc := fields(ts, "router-7", "sshd", "", "x")
	dashProc := fields(ts, "router-7", "sshd", "-", "x")
	if fingerprint(noProc) != fingerprint(dashProc) {
		t.Error(`"" and "-" must fold together for PROCID`)
	}
}

func TestFingerprint_DistinguishesDifferentMessages(t *testing.T) {
	ts := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	base := fields(ts, "router-7", "sshd", "1", "same text")

	cases := map[string]messageFields{
		"later timestamp": fields(ts.Add(time.Second), "router-7", "sshd", "1", "same text"),
		"other host":      fields(ts, "router-8", "sshd", "1", "same text"),
		"other app":       fields(ts, "router-7", "cron", "1", "same text"),
		"other pid":       fields(ts, "router-7", "sshd", "2", "same text"),
		"other text":      fields(ts, "router-7", "sshd", "1", "different"),
	}
	for name, other := range cases {
		if fingerprint(base) == fingerprint(other) {
			t.Errorf("%s: fingerprints collide", name)
		}
	}

	// Field boundaries must not be smearable: a host "ab" with app "c" is not
	// a host "a" with app "bc".
	a := fields(ts, "ab", "c", "", "")
	b := fields(ts, "a", "bc", "", "")
	if fingerprint(a) == fingerprint(b) {
		t.Error("field boundaries are not separated")
	}
}

func TestLoopGuard_SuppressesOnlyTheSecondSighting(t *testing.T) {
	g := newLoopGuard(time.Minute, 1000)
	now := time.Now()

	if g.seen(1, now) {
		t.Fatal("a message was suppressed on its first sighting")
	}
	if !g.seen(1, now) {
		t.Fatal("a repeat was not recognised")
	}
	if g.seen(2, now) {
		t.Fatal("an unrelated message was suppressed")
	}
}

func TestLoopGuard_ForgetsAfterTheWindow(t *testing.T) {
	g := newLoopGuard(time.Minute, 1000)
	start := time.Now()
	g.seen(1, start)

	// One rotation: still remembered, because the previous generation is kept.
	if !g.seen(1, start.Add(61*time.Second)) {
		t.Fatal("forgotten after a single rotation")
	}
	// A fingerprint untouched across two rotations is gone, so a device
	// legitimately repeating a line much later is forwarded again.
	g2 := newLoopGuard(time.Minute, 1000)
	g2.seen(9, start)
	g2.seen(0, start.Add(61*time.Second))  // rotate once
	g2.seen(0, start.Add(121*time.Second)) // rotate twice
	if g2.seen(9, start.Add(121*time.Second)) {
		t.Fatal("still suppressed long after the window")
	}
}

func TestLoopGuard_StaysBounded(t *testing.T) {
	const max = 100
	g := newLoopGuard(time.Hour, max)
	now := time.Now()
	for i := uint64(0); i < 10_000; i++ {
		g.seen(i, now)
	}
	g.mu.Lock()
	total := len(g.cur) + len(g.prev)
	g.mu.Unlock()
	if total > 2*max {
		t.Fatalf("guard holds %d entries, want at most %d", total, 2*max)
	}
}

func TestIsSelfDestination(t *testing.T) {
	local := LocalEndpoints{
		Ports: map[int]bool{1514: true, 6514: true},
		IPs:   map[string]bool{"192.168.1.113": true},
	}

	loops := []string{
		"127.0.0.1:1514",     // loopback, our port
		"localhost:1514",     // the name people actually type
		"0.0.0.0:1514",       // every interface, so including ours
		"192.168.1.113:6514", // our own LAN address
		"[::1]:1514",         // IPv6 loopback
	}
	for _, addr := range loops {
		if !IsSelfDestination(addr, local) {
			t.Errorf("%s was not recognised as pointing back at us", addr)
		}
	}

	fine := []string{
		"127.0.0.1:1515",     // our machine, a port we do not listen on
		"10.0.0.9:1514",      // our port, somebody else's machine
		"192.168.1.200:6514", // another host on the LAN
		"not-an-address",     // unparseable is not a loop
		"10.0.0.9:notaport",
	}
	for _, addr := range fine {
		if IsSelfDestination(addr, local) {
			t.Errorf("%s was wrongly refused as a loop", addr)
		}
	}

	// With nothing listening, nothing can be looped back into.
	if IsSelfDestination("127.0.0.1:1514", LocalEndpoints{}) {
		t.Error("a destination was called a loop with no listeners configured")
	}
}

// The end the feature exists for: a message that comes back is not relayed a
// second time, and the counter says so.
func TestDispatcher_CutsARelayLoop(t *testing.T) {
	d := NewDispatcher(nil, nil)
	defer d.Close()

	sink := SinkConfig{
		ID: "s1", Name: "far collector", Kind: SinkSyslog, Enabled: true,
		Syslog: SyslogSinkConfig{Address: "127.0.0.1:65000", Protocol: "udp", Facility: 16},
	}
	d.Configure([]Route{{
		ID: "r1", Name: "everything", Enabled: true, SinkIDs: []string{"s1"},
	}}, []SinkConfig{sink})

	msg := msgAt(models.SevWarning, "router-7", "sshd", "Accepted password for alice")

	d.Dispatch(msg)
	if got := d.Stats().Looped; got != 0 {
		t.Fatalf("the first sighting was counted as a loop (looped=%d)", got)
	}

	// The same message arriving again is the echo.
	d.Dispatch(msg)
	if got := d.Stats().Looped; got != 1 {
		t.Fatalf("looped = %d, want 1", got)
	}

	// A different message still gets through.
	other := msgAt(models.SevWarning, "router-7", "sshd", "Failed password for bob")
	d.Dispatch(other)
	if got := d.Stats().Looped; got != 1 {
		t.Fatalf("an unrelated message was suppressed (looped=%d)", got)
	}
	if got := d.Stats().Matched; got != 3 {
		t.Fatalf("matched = %d, want 3 — suppression must not hide the match", got)
	}
}

func TestDispatcher_SkipsASinkAimedAtOurselves(t *testing.T) {
	d := NewDispatcher(nil, nil)
	defer d.Close()

	d.SetLocalEndpoints(LocalEndpoints{Ports: map[int]bool{1514: true}})
	d.Configure([]Route{{
		ID: "r1", Name: "everything", Enabled: true, SinkIDs: []string{"s1"},
	}}, []SinkConfig{{
		ID: "s1", Name: "oops", Kind: SinkSyslog, Enabled: true,
		Syslog: SyslogSinkConfig{Address: "127.0.0.1:1514", Protocol: "udp", Facility: 16},
	}})

	d.Dispatch(msgAt(models.SevWarning, "router-7", "sshd", "hello"))
	if got := d.Stats().Looped; got != 1 {
		t.Fatalf("looped = %d, want 1 for a destination aimed at our own listener", got)
	}
	if got := d.Stats().Queued; got != 0 {
		t.Fatalf("%d jobs were queued for a self-destination", got)
	}
}

// Changing the routing table must not leave earlier suppressions in force,
// or a message would be held against a configuration it never met.
func TestDispatcher_ReconfiguringForgetsSuppressions(t *testing.T) {
	d := NewDispatcher(nil, nil)
	defer d.Close()

	routes := []Route{{ID: "r1", Name: "everything", Enabled: true, SinkIDs: []string{"s1"}}}
	sinks := []SinkConfig{{
		ID: "s1", Name: "far", Kind: SinkSyslog, Enabled: true,
		Syslog: SyslogSinkConfig{Address: "127.0.0.1:65000", Protocol: "udp", Facility: 16},
	}}
	d.Configure(routes, sinks)

	msg := msgAt(models.SevWarning, "router-7", "sshd", "hello")
	d.Dispatch(msg)
	d.Dispatch(msg)
	if got := d.Stats().Looped; got != 1 {
		t.Fatalf("looped = %d, want 1", got)
	}

	d.Configure(routes, sinks)
	d.Dispatch(msg)
	if got := d.Stats().Looped; got != 1 {
		t.Fatalf("looped = %d — reconfiguring did not clear the guard", got)
	}
}
