package headless

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/remote"
	"SyslogStudio/internal/storage"
)

// controlListener stands in for the service's pipe: what the host serves on
// it does not depend on the transport.
func controlListener(t *testing.T) net.Listener {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	return l
}

func connect(t *testing.T, l net.Listener) *remote.Client {
	t.Helper()
	conn, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	c, err := remote.NewClient(conn, "test", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

// A window connected to the host drives the host's engine, minus what a host
// with nobody at the keyboard cannot do.
func TestHost_WindowsDriveItsEngine(t *testing.T) {
	dir := t.TempDir()
	port := freeUDPPort(t)
	configure(t, dir, port)
	l := controlListener(t)
	h, err := Start(Options{DataDir: dir, Version: "test", Control: l})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()

	c := connect(t, l)
	if got := c.GetServerStatus(); !got.UDPRunning || got.Config.UDPPort != port {
		t.Fatalf("status seen from the window: %+v", got)
	}

	if err := c.EnableEncryption("secret"); err == nil || !strings.Contains(err.Error(), "encryption is not available") {
		t.Fatalf("EnableEncryption from a window: %v", err)
	}
	if h.eng.IsEncryptionEnabled() {
		t.Fatal("the host's database was encrypted")
	}

	st := c.GetStorageConfig()
	st.Path = `C:\Users\someone\Documents\logs.db`
	st.EncryptionEnabled = true
	c.SetStorageConfig(st)
	if got := h.eng.GetStorageConfig(); !strings.HasPrefix(got.Path, dir) || got.EncryptionEnabled {
		t.Fatalf("the window moved the host's database: %+v", got)
	}

	h.refresh()
	if n := h.Status().Windows; n != 1 {
		t.Fatalf("status counts %d windows, want 1", n)
	}

	// Stopping the host disconnects its windows.
	h.Stop()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the window was not disconnected when the host stopped")
	}
	if err := c.StopServer(); !errors.Is(err, remote.ErrClosed) {
		t.Fatalf("a call after the host stopped: %v", err)
	}
}

// A host windows can reach keeps running when its listeners cannot start —
// a port taken — so a window can change the settings; it says why, and
// starts them once the port is free.
func TestHost_KeepsRunningForWindowsWhenAPortIsTaken(t *testing.T) {
	dir := t.TempDir()
	taken, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := taken.LocalAddr().(*net.UDPAddr).Port
	configure(t, dir, port)

	l := controlListener(t)
	h, err := Start(Options{DataDir: dir, Version: "test", Control: l})
	if err != nil {
		taken.Close()
		t.Fatalf("a host windows can reach exited over a taken port: %v", err)
	}
	defer h.Stop()
	if st := h.Status(); st.State != "running" || !strings.Contains(st.Error, "start the listeners") {
		t.Fatalf("status with the port taken: %+v", st)
	}
	c := connect(t, l)
	if c.GetServerStatus().UDPRunning {
		t.Fatal("the UDP listener reports running on a taken port")
	}

	h.retryListeners()
	if st := h.Status(); st.Error == "" {
		t.Fatal("a retry with the port still taken cleared the error")
	}
	taken.Close()
	h.retryListeners()
	if st := h.Status(); st.Error != "" || !h.eng.GetServerStatus().UDPRunning {
		t.Fatalf("after the port was freed: %+v", st)
	}
}

// Once a window starts or stops the listeners, the host leaves them to it.
func TestHost_StopsRetryingOnceAWindowActs(t *testing.T) {
	dir := t.TempDir()
	taken, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	configure(t, dir, taken.LocalAddr().(*net.UDPAddr).Port)
	l := controlListener(t)
	h, err := Start(Options{DataDir: dir, Version: "test", Control: l})
	if err != nil {
		taken.Close()
		t.Fatal(err)
	}
	defer h.Stop()

	c := connect(t, l)
	if err := c.StopServer(); err != nil {
		t.Fatal(err)
	}
	taken.Close()
	h.retryListeners()
	if h.eng.GetServerStatus().Running {
		t.Fatal("the host restarted listeners a window had stopped")
	}
}

// Without windows to fix things, a host that cannot listen exits, so its
// supervisor restarts it and says so.
func TestHost_WithoutWindowsATakenPortIsFatal(t *testing.T) {
	dir := t.TempDir()
	taken, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer taken.Close()
	configure(t, dir, taken.LocalAddr().(*net.UDPAddr).Port)
	if h, err := Start(Options{DataDir: dir}); err == nil {
		h.Stop()
		t.Fatal("started with its only port taken")
	}
	if st, _ := ReadStatus(dir); st.State != "failed" {
		t.Fatalf("status: %+v", st)
	}
}

// Listening on start turned off, from a window: the host starts, for its
// windows, and its listeners wait for one to press Start.
func TestHost_ListeningOnStartOffWaitsForAWindow(t *testing.T) {
	dir := t.TempDir()
	port := freeUDPPort(t)
	configure(t, dir, port)
	storage.NewConfigStoreAt(dir).SaveListenOnStart(false)

	l := controlListener(t)
	h, err := Start(Options{DataDir: dir, Version: "test", Control: l})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()
	if h.eng.GetServerStatus().Running {
		t.Fatal("listening although listening on start is off")
	}
	if st := h.Status(); st.State != "running" || st.Error != "" || st.ListenOnStart {
		t.Fatalf("status: %+v", st)
	}

	c := connect(t, l)
	if c.GetListenOnStart() {
		t.Fatal("the window sees listening on start as on")
	}
	if err := c.StartServer(c.GetDefaultConfig()); err != nil {
		t.Fatal(err)
	}
	if st := c.GetServerStatus(); !st.UDPRunning || st.Config.UDPPort != port {
		t.Fatalf("after the window's Start: %+v", st)
	}

	c.SetListenOnStart(true)
	h.refresh()
	if !h.Status().ListenOnStart {
		t.Fatal("the window turned listening on start back on; the status still says off")
	}
}

// A host no window can reach has nobody to press Start: it listens anyway.
func TestHost_WithoutWindowsListensRegardless(t *testing.T) {
	dir := t.TempDir()
	configure(t, dir, freeUDPPort(t))
	storage.NewConfigStoreAt(dir).SaveListenOnStart(false)

	h, err := Start(Options{DataDir: dir, Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	defer h.Stop()
	if !h.eng.GetServerStatus().UDPRunning {
		t.Fatal("a host nobody can drive waits for a window")
	}
}
