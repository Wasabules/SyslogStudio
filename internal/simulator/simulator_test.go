package simulator

import (
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/syslog"
)

// udpSink is a throwaway collector: it stands in for the real listener so the
// tests assert on bytes that actually crossed a socket, not on a formatter's
// return value.
type udpSink struct {
	conn *net.UDPConn
	mu   sync.Mutex
	msgs []string
}

func newUDPSink(t *testing.T) *udpSink {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s := &udpSink{conn: conn}
	go s.read()
	t.Cleanup(func() { conn.Close() })
	return s
}

func (s *udpSink) read() {
	buf := make([]byte, 65535)
	for {
		n, _, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		s.mu.Lock()
		s.msgs = append(s.msgs, string(buf[:n]))
		s.mu.Unlock()
	}
}

func (s *udpSink) port() int { return s.conn.LocalAddr().(*net.UDPAddr).Port }

func (s *udpSink) received() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, len(s.msgs))
	copy(out, s.msgs)
	return out
}

// waitFor polls until cond holds or the deadline passes, which is how a test
// waits on a network send without sleeping for a fixed guess.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) bool {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(10 * time.Millisecond)
	}
	return cond()
}

func destTo(port int) models.SimulatorDestination {
	return models.SimulatorDestination{
		ID: "t1", Name: "sink", Host: "127.0.0.1",
		Port: port, Protocol: "udp", Enabled: true,
	}
}

// The messages the simulator emits must be the messages the collector parses.
// Asserting round-trip through the real parser is the only way to know the
// generator is not quietly producing something subtly unparseable.
func TestSimulator_OutputParsesBackInBothFormats(t *testing.T) {
	for _, format := range []string{"rfc5424", "rfc3164"} {
		t.Run(format, func(t *testing.T) {
			sink := newUDPSink(t)
			sim := New(event.NewMockEventEmitter())

			cfg := models.DefaultSimulatorConfig()
			cfg.Destinations = []models.SimulatorDestination{destTo(sink.port())}
			cfg.Mode = models.SimModeBurst
			cfg.Count = 40
			cfg.Format = format

			if err := sim.Start(cfg); err != nil {
				t.Fatalf("Start: %v", err)
			}
			t.Cleanup(func() { sim.Stop() })

			if !waitFor(t, 5*time.Second, func() bool { return len(sink.received()) >= 30 }) {
				t.Fatalf("only %d messages arrived", len(sink.received()))
			}

			wantVersion := 1
			if format == "rfc3164" {
				wantVersion = 0
			}
			for _, wire := range sink.received() {
				msg := syslog.Parse([]byte(wire), "127.0.0.1", "UDP")
				if msg.Version != wantVersion {
					t.Fatalf("parsed as version %d, want %d\n  wire: %s", msg.Version, wantVersion, wire)
				}
				if msg.Hostname == "" {
					t.Errorf("hostname did not survive the round trip: %s", wire)
				}
				if msg.AppName == "" {
					t.Errorf("app name did not survive the round trip: %s", wire)
				}
				if msg.Message == "" {
					t.Errorf("message body is empty: %s", wire)
				}
				// An unfilled placeholder means a template names a key the
				// filler does not know, which would ship as literal "{pid}".
				if strings.Contains(msg.Message, "{") && strings.Contains(msg.Message, "}") {
					t.Errorf("unfilled placeholder in %q", msg.Message)
				}
			}
		})
	}
}

func TestSimulator_CustomMessageIsSentVerbatim(t *testing.T) {
	sink := newUDPSink(t)
	sim := New(event.NewMockEventEmitter())

	const custom = "Failed password for root from 203.0.113.9 port 22 ssh2"
	cfg := models.DefaultSimulatorConfig()
	cfg.Destinations = []models.SimulatorDestination{destTo(sink.port())}
	cfg.Mode = models.SimModeBurst
	cfg.Count = 5
	cfg.CustomMessage = custom
	cfg.Hostname = "bastion-01"
	cfg.AppName = "sshd"

	if err := sim.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { sim.Stop() })

	if !waitFor(t, 5*time.Second, func() bool { return len(sink.received()) >= 5 }) {
		t.Fatalf("only %d messages arrived", len(sink.received()))
	}
	for _, wire := range sink.received() {
		msg := syslog.Parse([]byte(wire), "127.0.0.1", "UDP")
		if msg.Message != custom {
			t.Errorf("message = %q, want %q", msg.Message, custom)
		}
		if msg.Hostname != "bastion-01" || msg.AppName != "sshd" {
			t.Errorf("overrides lost: hostname=%q app=%q", msg.Hostname, msg.AppName)
		}
	}
}

// Several collectors at once is the point of the feature: the same stream has
// to reach all of them.
func TestSimulator_FansOutToEveryEnabledDestination(t *testing.T) {
	a, b, disabled := newUDPSink(t), newUDPSink(t), newUDPSink(t)
	sim := New(event.NewMockEventEmitter())

	cfg := models.DefaultSimulatorConfig()
	cfg.Destinations = []models.SimulatorDestination{
		{ID: "a", Name: "A", Host: "127.0.0.1", Port: a.port(), Protocol: "udp", Enabled: true},
		{ID: "b", Name: "B", Host: "127.0.0.1", Port: b.port(), Protocol: "udp", Enabled: true},
		{ID: "c", Name: "C", Host: "127.0.0.1", Port: disabled.port(), Protocol: "udp", Enabled: false},
	}
	cfg.Mode = models.SimModeBurst
	cfg.Count = 20

	if err := sim.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { sim.Stop() })

	ok := waitFor(t, 5*time.Second, func() bool {
		return len(a.received()) >= 15 && len(b.received()) >= 15
	})
	if !ok {
		t.Fatalf("A got %d, B got %d", len(a.received()), len(b.received()))
	}
	if got := len(disabled.received()); got != 0 {
		t.Errorf("disabled destination received %d messages", got)
	}

	st := sim.Status()
	if len(st.Destinations) != 2 {
		t.Errorf("status reports %d destinations, want 2 (disabled excluded)", len(st.Destinations))
	}
}

func TestSimulator_RefusesASecondRun(t *testing.T) {
	sink := newUDPSink(t)
	sim := New(event.NewMockEventEmitter())

	cfg := models.DefaultSimulatorConfig()
	cfg.Destinations = []models.SimulatorDestination{destTo(sink.port())}
	cfg.Rate = 5 // continuous, so it stays running

	if err := sim.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { sim.Stop() })

	if err := sim.Start(cfg); err == nil {
		t.Fatal("a second Start was accepted while a run was in progress")
	}
}

// Stop must be synchronous: a Start straight afterwards would otherwise race
// the previous run's sends and the counters would be nonsense.
func TestSimulator_StopIsSynchronousAndRestartable(t *testing.T) {
	sink := newUDPSink(t)
	sim := New(event.NewMockEventEmitter())

	cfg := models.DefaultSimulatorConfig()
	cfg.Destinations = []models.SimulatorDestination{destTo(sink.port())}
	cfg.Rate = 50

	if err := sim.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	waitFor(t, 3*time.Second, func() bool { return sim.Status().Sent > 0 })

	if err := sim.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if sim.Status().Running {
		t.Error("still running after Stop returned")
	}

	// Counters reset on the next run rather than accumulating across runs.
	if err := sim.Start(cfg); err != nil {
		t.Fatalf("restart: %v", err)
	}
	t.Cleanup(func() { sim.Stop() })
	if got := sim.Status().Sent; got > 100 {
		t.Errorf("Sent = %d immediately after restart; counters did not reset", got)
	}
}

func TestSimulator_DurationStopsTheRun(t *testing.T) {
	sink := newUDPSink(t)
	sim := New(event.NewMockEventEmitter())

	cfg := models.DefaultSimulatorConfig()
	cfg.Destinations = []models.SimulatorDestination{destTo(sink.port())}
	cfg.Rate = 50
	cfg.DurationSeconds = 1

	if err := sim.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { sim.Stop() })

	if !waitFor(t, 6*time.Second, func() bool { return !sim.Status().Running }) {
		t.Fatal("run did not stop on its own after the configured duration")
	}
}

// A destination that is not listening must be reported, not silently counted as
// delivered — otherwise "sent: 5000" would mean nothing.
func TestSimulator_ReportsAnUnreachableTCPDestination(t *testing.T) {
	// Port 1 on loopback: reserved, and nothing will be listening.
	sim := New(event.NewMockEventEmitter())
	cfg := models.DefaultSimulatorConfig()
	cfg.Destinations = []models.SimulatorDestination{{
		ID: "dead", Name: "closed port", Host: "127.0.0.1",
		Port: 1, Protocol: "tcp", Enabled: true,
	}}
	cfg.Mode = models.SimModeBurst
	cfg.Count = 5

	if err := sim.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { sim.Stop() })

	ok := waitFor(t, 15*time.Second, func() bool {
		st := sim.Status()
		return st.Failed > 0 && len(st.Destinations) == 1 && st.Destinations[0].LastError != ""
	})
	if !ok {
		st := sim.Status()
		t.Fatalf("failures not reported: sent=%d failed=%d dests=%+v", st.Sent, st.Failed, st.Destinations)
	}
	if st := sim.Status(); st.Destinations[0].Connected {
		t.Error("an unreachable destination is reported as connected")
	}
}

func TestSimulator_StatusEventsAreEmitted(t *testing.T) {
	sink := newUDPSink(t)
	emitter := event.NewMockEventEmitter()
	sim := New(emitter)

	cfg := models.DefaultSimulatorConfig()
	cfg.Destinations = []models.SimulatorDestination{destTo(sink.port())}
	cfg.Rate = 20

	if err := sim.Start(cfg); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { sim.Stop() })

	ok := waitFor(t, 5*time.Second, func() bool {
		for _, e := range emitter.GetEvents() {
			if e.Name == "syslog:simulatorStatus" {
				return true
			}
		}
		return false
	})
	if !ok {
		t.Error("no syslog:simulatorStatus event was emitted")
	}
}

func TestWeightedSeverity_FollowsTheProfile(t *testing.T) {
	// A quiet server is mostly info and debug; a critical one is mostly errors
	// and worse. Asserting the shape, not exact proportions, keeps this stable
	// while still catching a profile table that got mixed up.
	const draws = 4000

	countSevere := func(profile models.SimulatorProfile) int {
		severe := 0
		for i := 0; i < draws; i++ {
			if weightedSeverity(profile) <= models.SevError {
				severe++
			}
		}
		return severe
	}

	quiet := countSevere(models.SimProfileQuiet)
	normal := countSevere(models.SimProfileNormal)
	critical := countSevere(models.SimProfileCritical)

	if !(quiet < normal && normal < critical) {
		t.Errorf("severe share should rise with the profile, got quiet=%d normal=%d critical=%d",
			quiet, normal, critical)
	}
	if quiet > draws/5 {
		t.Errorf("quiet produced %d/%d severe messages, which is not a quiet server", quiet, draws)
	}
	if critical < draws/2 {
		t.Errorf("critical produced only %d/%d severe messages", critical, draws)
	}
}

func TestValidateSimulatorConfig(t *testing.T) {
	base := models.DefaultSimulatorConfig()

	tests := []struct {
		name    string
		mutate  func(*models.SimulatorConfig)
		wantErr bool
	}{
		{"defaults are runnable", func(c *models.SimulatorConfig) {}, false},
		{"no destination enabled", func(c *models.SimulatorConfig) {
			c.Destinations[0].Enabled = false
		}, true},
		{"empty host", func(c *models.SimulatorConfig) { c.Destinations[0].Host = "" }, true},
		{"hostname is allowed", func(c *models.SimulatorConfig) {
			c.Destinations[0].Host = "collector.example.com"
		}, false},
		{"port out of range", func(c *models.SimulatorConfig) { c.Destinations[0].Port = 70000 }, true},
		{"unknown protocol", func(c *models.SimulatorConfig) { c.Destinations[0].Protocol = "sctp" }, true},
		{"rate zero", func(c *models.SimulatorConfig) { c.Rate = 0 }, true},
		{"rate above the cap", func(c *models.SimulatorConfig) {
			c.Rate = models.MaxSimulatorRate + 1
		}, true},
		{"burst count zero", func(c *models.SimulatorConfig) {
			c.Mode, c.Count = models.SimModeBurst, 0
		}, true},
		{"scenario ignores rate", func(c *models.SimulatorConfig) {
			c.Mode, c.Rate = models.SimModeScenario, 0
		}, false},
		{"alert test ignores rate", func(c *models.SimulatorConfig) {
			c.Mode, c.Rate = models.SimModeAlertTest, 0
		}, false},
		{"unknown mode", func(c *models.SimulatorConfig) { c.Mode = "hammer" }, true},
		{"unknown format", func(c *models.SimulatorConfig) { c.Format = "cef" }, true},
		{"negative duration", func(c *models.SimulatorConfig) { c.DurationSeconds = -1 }, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := base
			cfg.Destinations = append([]models.SimulatorDestination(nil), base.Destinations...)
			tt.mutate(&cfg)
			err := models.ValidateSimulatorConfig(cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestScenarioDuration(t *testing.T) {
	// The UI shows progress against this, so it must match the phase table.
	var sum time.Duration
	for _, p := range scenarioPhases {
		sum += p.Duration
	}
	if got := ScenarioDuration(); got != sum {
		t.Errorf("ScenarioDuration() = %v, want %v", got, sum)
	}
	if sum == 0 {
		t.Fatal("the scenario has no phases")
	}
}

func TestAlertTestCases_AreParseableAndSevere(t *testing.T) {
	// These exist to trip alert rules, so each must parse and carry the
	// severity the rule would match on.
	for _, tc := range alertTestCases {
		g := buildFixed("rfc5424", tc.Severity, tc.Facility, tc.Hostname, tc.AppName, tc.Message)
		msg := syslog.Parse([]byte(g.Wire), "127.0.0.1", "UDP")
		if msg.Severity != tc.Severity {
			t.Errorf("%q parsed as severity %d, want %d", tc.Message, msg.Severity, tc.Severity)
		}
		if msg.Message != tc.Message {
			t.Errorf("message changed in transit: got %q want %q", msg.Message, tc.Message)
		}
		if tc.Severity > models.SevWarning {
			t.Errorf("%q has severity %d, too mild to be an alert test case", tc.Message, tc.Severity)
		}
	}
	if len(alertTestCases) == 0 {
		t.Fatal("no alert test cases")
	}
}
