package simulator

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
)

const (
	// statusInterval is how often the frontend is told where the run is.
	statusInterval = 500 * time.Millisecond
	// maxTickRate caps how often the pacing loop wakes. Above it, messages are
	// sent in batches per tick instead: a 50k/s run would otherwise need a
	// 20µs timer, which no OS scheduler honours and which burns a core doing
	// nothing but waking up.
	maxTickRate = 200
)

// Simulator generates syslog traffic and sends it to one or more collectors.
// One run at a time; Start refuses while a run is in progress rather than
// silently interleaving two rates.
type Simulator struct {
	emitter event.EventEmitter

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
	cfg     models.SimulatorConfig
	senders []*sender
	started time.Time

	sent   atomic.Int64
	failed atomic.Int64

	// phase is an atomic.Value rather than a mutex-guarded field: it is written
	// by the scenario loop and read by every status poll, and holding the main
	// mutex for it would serialise status reads against Start/Stop.
	phase atomic.Value // string
}

// New creates a Simulator. The emitter carries status to the frontend.
func New(emitter event.EventEmitter) *Simulator {
	s := &Simulator{emitter: emitter}
	s.phase.Store("")
	return s
}

// Start validates the config and begins a run. It returns as soon as the run is
// under way; progress arrives through syslog:simulatorStatus events.
func (s *Simulator) Start(cfg models.SimulatorConfig) error {
	if err := models.ValidateSimulatorConfig(cfg); err != nil {
		return err
	}

	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return fmt.Errorf("a simulation is already running")
	}

	var senders []*sender
	for _, d := range cfg.Destinations {
		if d.Enabled {
			senders = append(senders, newSender(d))
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.running = true
	s.cancel = cancel
	s.done = make(chan struct{})
	s.cfg = cfg
	s.senders = senders
	s.started = time.Now()
	s.sent.Store(0)
	s.failed.Store(0)
	s.phase.Store("")
	done := s.done
	s.mu.Unlock()

	slog.Info("simulator started", "mode", cfg.Mode, "destinations", len(senders),
		"profile", cfg.Profile, "format", cfg.Format)

	go func() {
		defer close(done)
		s.run(ctx, cfg, senders)
	}()
	go s.publishStatus(ctx, done)
	return nil
}

// Stop ends the current run and waits for it to unwind, so a Start immediately
// afterwards does not race the previous run's sends.
func (s *Simulator) Stop() error {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return nil
	}
	cancel := s.cancel
	done := s.done
	s.mu.Unlock()

	cancel()
	<-done
	return nil
}

// Status reports the live state of the run.
func (s *Simulator) Status() models.SimulatorStatus {
	s.mu.Lock()
	running := s.running
	cfg := s.cfg
	senders := s.senders
	started := s.started
	s.mu.Unlock()

	st := models.SimulatorStatus{
		Running: running,
		Mode:    cfg.Mode,
		Sent:    s.sent.Load(),
		Failed:  s.failed.Load(),
	}
	if phase, _ := s.phase.Load().(string); phase != "" {
		st.Phase = phase
	}
	if !started.IsZero() {
		elapsed := time.Since(started)
		st.ElapsedMs = elapsed.Milliseconds()
		if secs := elapsed.Seconds(); secs > 0 {
			st.RatePerSec = float64(st.Sent) / secs
		}
	}
	for _, snd := range senders {
		st.Destinations = append(st.Destinations, snd.status())
	}
	return st
}

// run dispatches to the mode's loop and cleans up afterwards.
func (s *Simulator) run(ctx context.Context, cfg models.SimulatorConfig, senders []*sender) {
	defer func() {
		for _, snd := range senders {
			snd.close()
		}
		s.mu.Lock()
		s.running = false
		s.mu.Unlock()
		s.phase.Store("")
		// A final status so the UI settles on the real totals rather than
		// whatever the last periodic tick happened to catch.
		s.emit()
		slog.Info("simulator stopped", "sent", s.sent.Load(), "failed", s.failed.Load())
	}()

	switch cfg.Mode {
	case models.SimModeBurst:
		s.runBurst(ctx, cfg, senders)
	case models.SimModeScenario:
		s.runScenario(ctx, cfg, senders)
	case models.SimModeAlertTest:
		s.runAlertTest(ctx, cfg, senders)
	default:
		deadline := time.Time{}
		if cfg.DurationSeconds > 0 {
			deadline = time.Now().Add(time.Duration(cfg.DurationSeconds) * time.Second)
		}
		s.runAtRate(ctx, cfg, senders, cfg.Rate, deadline)
	}
}

// runAtRate emits at a steady rate until the deadline, or until cancelled when
// the deadline is zero.
func (s *Simulator) runAtRate(ctx context.Context, cfg models.SimulatorConfig, senders []*sender, rate float64, deadline time.Time) {
	if rate <= 0 {
		return
	}
	// Above maxTickRate the loop keeps a fixed tick and sends a batch each
	// time, because sub-millisecond timers are not honoured by the scheduler.
	perTick := 1
	tick := time.Duration(float64(time.Second) / rate)
	if rate > maxTickRate {
		tick = time.Second / maxTickRate
		perTick = int(rate / maxTickRate)
		if perTick < 1 {
			perTick = 1
		}
	}

	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !deadline.IsZero() && time.Now().After(deadline) {
				return
			}
			for i := 0; i < perTick; i++ {
				s.emitOne(build(cfg), senders)
			}
		}
	}
}

// runBurst sends a fixed count as fast as the transport allows, checking for
// cancellation often enough that Stop is responsive on a large burst.
func (s *Simulator) runBurst(ctx context.Context, cfg models.SimulatorConfig, senders []*sender) {
	for i := 0; i < cfg.Count; i++ {
		if i%256 == 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
		s.emitOne(build(cfg), senders)
	}
}

// runScenario walks the incident timeline, reporting the current phase so the
// UI can show what the traffic is meant to represent.
func (s *Simulator) runScenario(ctx context.Context, cfg models.SimulatorConfig, senders []*sender) {
	for _, phase := range scenarioPhases {
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.phase.Store(phase.Name)
		phaseCfg := cfg
		phaseCfg.Profile = phase.Profile
		s.runAtRate(ctx, phaseCfg, senders, phase.Rate, time.Now().Add(phase.Duration))
	}
}

// runAlertTest sends the fixed alert-shaped messages, spaced enough that they
// arrive as distinct events rather than one indistinguishable clump.
func (s *Simulator) runAlertTest(ctx context.Context, cfg models.SimulatorConfig, senders []*sender) {
	for _, tc := range alertTestCases {
		select {
		case <-ctx.Done():
			return
		case <-time.After(400 * time.Millisecond):
		}
		s.emitOne(buildFixed(cfg.Format, tc.Severity, tc.Facility, tc.Hostname, tc.AppName, tc.Message), senders)
	}
}

// emitOne sends one message to every destination and counts it once per
// destination, which is what "sent" means when several collectors are targeted.
func (s *Simulator) emitOne(g generated, senders []*sender) {
	for _, snd := range senders {
		before := snd.failed.Load()
		snd.send(g.Wire)
		if snd.failed.Load() > before {
			s.failed.Add(1)
		} else {
			s.sent.Add(1)
		}
	}
}

func (s *Simulator) publishStatus(ctx context.Context, done <-chan struct{}) {
	ticker := time.NewTicker(statusInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
			s.emit()
		}
	}
}

func (s *Simulator) emit() {
	if s.emitter != nil {
		s.emitter.Emit("syslog:simulatorStatus", s.Status())
	}
}
