package remote

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
)

// events collects what a client receives.
type events struct {
	mu   sync.Mutex
	got  []string
	data map[string][]json.RawMessage
}

func (e *events) on(name string, data []json.RawMessage) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.got = append(e.got, name)
	if e.data == nil {
		e.data = map[string][]json.RawMessage{}
	}
	e.data[name] = data
}

func (e *events) last(name string) []json.RawMessage {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.data[name]
}

// pair opens an engine in a temporary directory, serves it, and connects a
// client to it over an in-memory pipe.
func pair(t *testing.T, host func(*engine.Engine) Host) (*engine.Engine, *Server, *Client, *events) {
	t.Helper()
	eng := engine.New(storage.NewConfigStoreAt(t.TempDir()))
	var h Host = eng
	if host != nil {
		h = host(eng)
	}
	srv := NewServer(h, "v-test", nil)
	if err := eng.Open(srv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		srv.Close()
		eng.Close()
	})

	window, service := net.Pipe()
	go srv.ServeConn(service)
	ev := &events{}
	c, err := NewClient(window, "v-test", ev.on)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return eng, srv, c, ev
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// What the user ran into: the window's settings must be the service's. A
// port changed from the window is the port the service listens on, and what
// arrives there is what the window shows.
func TestClient_DrivesTheServiceEngine(t *testing.T) {
	eng, _, c, ev := pair(t, nil)

	cfg := c.GetDefaultConfig()
	cfg.UDPEnabled, cfg.TCPEnabled, cfg.TLSEnabled = true, false, false
	cfg.UDPPort = freeUDPPort(t)
	cfg.BindAddress = "127.0.0.1"
	if err := c.StartServer(cfg); err != nil {
		t.Fatal(err)
	}
	if got := eng.GetDefaultConfig().UDPPort; got != cfg.UDPPort {
		t.Fatalf("the service saved port %d, the window asked for %d", got, cfg.UDPPort)
	}
	if st := c.GetServerStatus(); !st.Running || !st.UDPRunning || st.Config.UDPPort != cfg.UDPPort {
		t.Fatalf("status seen from the window: %+v", st)
	}

	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", cfg.UDPPort))
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprint(conn, "<11>1 2026-10-20T12:00:00Z svc-host svc-app - - - seen from the window")
	conn.Close()

	// Live, as an event, the way the in-process engine shows it...
	waitFor(t, "the message event", func() bool { return ev.last("syslog:messages") != nil })
	var batch []models.SyslogMessage
	if err := json.Unmarshal(ev.last("syslog:messages")[0], &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch) != 1 || batch[0].Message != "seen from the window" || batch[0].Hostname != "svc-host" {
		t.Fatalf("batch: %+v", batch)
	}
	// ...and on request.
	msgs := c.GetMessages(models.FilterCriteria{})
	if len(msgs) != 1 || msgs[0].Message != "seen from the window" {
		t.Fatalf("GetMessages: %+v", msgs)
	}
	if n := c.GetStats().TotalMessages; n != 1 {
		t.Fatalf("stats: %d messages", n)
	}

	if err := c.StopServer(); err != nil {
		t.Fatal(err)
	}
	if eng.GetServerStatus().Running {
		t.Fatal("the window stopped the listeners, the service still runs them")
	}
}

func TestClient_ReturnsTheEnginesErrors(t *testing.T) {
	_, _, c, _ := pair(t, nil)
	cfg := c.GetDefaultConfig()
	cfg.UDPEnabled = true
	cfg.UDPPort = 70000
	err := c.StartServer(cfg)
	var re *RemoteError
	if !errors.As(err, &re) || !strings.Contains(err.Error(), "70000") {
		t.Fatalf("StartServer with a bad port: %v", err)
	}
	// The connection is still usable afterwards.
	if c.GetDefaultConfig().UDPPort == 0 {
		t.Fatal("no answer after an error")
	}
}

type panicky struct{ *engine.Engine }

func (panicky) GetStats() models.ServerStats { panic("boom") }

// One call that panics in the service must not take the service down, nor
// the window's connection.
func TestServer_APanicIsAnError(t *testing.T) {
	_, _, c, _ := pair(t, func(e *engine.Engine) Host { return panicky{e} })
	var stats models.ServerStats
	err := c.call("GetStats", []any{}, &stats)
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("panicking call: %v", err)
	}
	if c.GetDefaultConfig().UDPPort == 0 {
		t.Fatal("no answer after the panic")
	}
}

func TestServer_OnlyAnswersTheHostMethods(t *testing.T) {
	_, _, c, _ := pair(t, nil)
	// Exported on the engine, but not part of what windows may call.
	if err := c.call("ExportBundle", []any{}); err == nil || !strings.Contains(err.Error(), "no method") {
		t.Fatalf("ExportBundle over the wire: %v", err)
	}
	if err := c.call("Close", []any{}); err == nil {
		t.Fatal("Close over the wire was answered")
	}
}

func TestNewClient_RefusesAnotherBuild(t *testing.T) {
	eng := engine.New(storage.NewConfigStoreAt(t.TempDir()))
	srv := NewServer(eng, "v1.7.0", nil)
	defer srv.Close()
	window, service := net.Pipe()
	go srv.ServeConn(service)

	_, err := NewClient(window, "v1.6.1", nil)
	var verr *VersionError
	if !errors.As(err, &verr) || verr.Service != "v1.7.0" || verr.Window != "v1.6.1" {
		t.Fatalf("mismatched versions: %v", err)
	}
}

func TestClient_KnowsWhenTheServiceGoesAway(t *testing.T) {
	_, srv, c, _ := pair(t, nil)
	srv.Close()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the client did not notice the service closing")
	}
	if err := c.StopServer(); !errors.Is(err, ErrClosed) {
		t.Fatalf("a call after the loss: %v", err)
	}
}

// A window that stops reading is disconnected rather than allowed to hold up
// the engine emitting to it.
func TestServer_DisconnectsAWindowThatStopsReading(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	eng := engine.New(storage.NewConfigStoreAt(t.TempDir()))
	srv := NewServer(eng, "", nil)
	defer srv.Close()
	window, service := net.Pipe()
	go srv.ServeConn(service)
	c, err := NewClient(window, "", func(string, []json.RawMessage) { <-block })
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	done := make(chan struct{})
	go func() {
		for i := 0; i < eventQueue+10; i++ {
			srv.Emit("syslog:stats", i)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Emit waited for a window that does not read")
	}
	waitFor(t, "the window to be dropped", func() bool { return srv.Windows() == 0 })
}

// The file to import is the window user's: the window reads it and the
// service only receives the messages.
func TestClient_ImportsAFileItReadsItself(t *testing.T) {
	eng, _, c, _ := pair(t, nil)
	path := filepath.Join(t.TempDir(), "app.log")
	lines := "2026-10-20 10:00:00 ERROR disk full\n2026-10-20 10:00:01 INFO recovered\n"
	if err := os.WriteFile(path, []byte(lines), 0644); err != nil {
		t.Fatal(err)
	}
	format := models.DefaultImportFormat()

	prev, err := c.PreviewLogFile(path, format)
	if err != nil || len(prev.Messages) != 2 {
		t.Fatalf("preview: %d messages, %v", len(prev.Messages), err)
	}
	if n := len(eng.GetMessages(models.FilterCriteria{})); n != 0 {
		t.Fatalf("a preview reached the service: %d messages", n)
	}

	res, err := c.ImportLogFile(path, false, format)
	if err != nil || res.Imported != 2 {
		t.Fatalf("import: %+v, %v", res, err)
	}
	got := eng.GetMessages(models.FilterCriteria{})
	if len(got) != 2 {
		t.Fatalf("the service has %d messages, want 2", len(got))
	}
}

func TestSwitch_ForwardsToTheCurrentBackend(t *testing.T) {
	a := engine.New(storage.NewConfigStoreAt(t.TempDir()))
	b := engine.New(storage.NewConfigStoreAt(t.TempDir()))
	cfg := b.GetDefaultConfig()
	cfg.UDPPort = 5514
	b.SaveServerConfig(cfg)

	sw := NewSwitch(a)
	if sw.GetDefaultConfig().UDPPort == 5514 {
		t.Fatal("the first backend already had the second's port")
	}
	sw.Set(b)
	if got := sw.GetDefaultConfig().UDPPort; got != 5514 {
		t.Fatalf("after Set: port %d", got)
	}
}
