package headless

import (
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
)

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// configure writes what the desktop application would have saved: a UDP
// listener on loopback.
func configure(t *testing.T, dir string, port int) {
	t.Helper()
	cs := storage.NewConfigStoreAt(dir)
	cfg := models.DefaultServerConfig()
	cfg.UDPEnabled, cfg.TCPEnabled, cfg.TLSEnabled = true, false, false
	cfg.UDPPort = port
	cfg.BindAddress = "127.0.0.1"
	cs.Save(cfg)
	st := cs.LoadStorage()
	st.Enabled = true
	cs.SaveStorage(st)
}

// What the service does on boot: start from the saved configuration, with no
// one pressing Start, receive, and keep what it received.
func TestHost_ReceivesAndStoresWithoutAWindow(t *testing.T) {
	dir := t.TempDir()
	port := freeUDPPort(t)
	configure(t, dir, port)

	h, err := Start(Options{DataDir: dir, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if st, ok := ReadStatus(dir); !ok || st.State != "running" || len(st.Listeners) != 1 || !st.Listeners[0].Running {
		t.Fatalf("published status: %+v (ok=%v)", st, ok)
	}

	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		fmt.Fprintf(conn, "<134>1 2026-03-17T21:42:1%dZ web-1 sshd - - - unattended %d", i, i)
	}
	conn.Close()

	deadline := time.Now().Add(5 * time.Second)
	for h.eng.GetStats().TotalMessages < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := h.eng.GetStats().TotalMessages; n < 3 {
		t.Fatalf("received %d messages, want 3", n)
	}
	h.Stop()

	if st, _ := ReadStatus(dir); st.State != "stopped" {
		t.Errorf("status after stop: %q", st.State)
	}

	// The messages are in the database, for whoever opens it next.
	e := engine.New(storage.NewConfigStoreAt(dir))
	if err := e.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	deadline = time.Now().Add(5 * time.Second)
	for !e.IsStorageReady() && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if got := e.QueryMessages(models.QueryOptions{Page: 1, PageSize: 10}); got.Total != 3 {
		t.Fatalf("the database holds %d messages, want 3", got.Total)
	}
}

// With encryption on, every message would be received and none stored. The
// host refuses, and says why where an operator will look.
func TestHost_RefusesAnEncryptedConfiguration(t *testing.T) {
	dir := t.TempDir()
	configure(t, dir, freeUDPPort(t))
	cs := storage.NewConfigStoreAt(dir)
	st := cs.LoadStorage()
	st.EncryptionEnabled = true
	cs.SaveStorage(st)

	if _, err := Start(Options{DataDir: dir}); !errors.Is(err, ErrEncrypted) {
		t.Fatalf("got %v, want ErrEncrypted", err)
	}
	if got, _ := ReadStatus(dir); got.State != "failed" || got.Error == "" {
		t.Errorf("the failure was not published: %+v", got)
	}
}

// Two engines on one directory would both write the same database.
func TestHost_RefusesADirectoryInUse(t *testing.T) {
	dir := t.TempDir()
	configure(t, dir, freeUDPPort(t))
	first, err := Start(Options{DataDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer first.Stop()

	if _, err := Start(Options{DataDir: dir}); !errors.Is(err, storage.ErrDirInUse) {
		t.Fatalf("a second host on the same directory: got %v, want ErrDirInUse", err)
	}
	// The refused host must not speak for the running one.
	if st, _ := ReadStatus(dir); st.State != "running" || st.PID != first.Status().PID {
		t.Fatalf("the running host's status was overwritten: %+v", st)
	}
}
