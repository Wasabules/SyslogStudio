package main

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
)

// openApp builds the window's side around an engine opened on a temporary
// directory, the way startup does minus Wails.
func openApp(t *testing.T) *App {
	t.Helper()
	a := newAppIn(storage.NewConfigStoreAt(t.TempDir()))
	if err := a.engine.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.engine.Close)
	return a
}

func udpConfig(t *testing.T) models.ServerConfig {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := c.LocalAddr().(*net.UDPAddr).Port
	c.Close()
	cfg := models.DefaultServerConfig()
	cfg.UDPEnabled, cfg.TCPEnabled, cfg.TLSEnabled = true, false, false
	cfg.UDPPort = port
	cfg.BindAddress = "127.0.0.1"
	return cfg
}

func TestAutoStart_StartsTheSavedListenersOnlyWhenAsked(t *testing.T) {
	a := openApp(t)
	a.SaveServerConfig(udpConfig(t))

	a.autoStart()
	if a.GetServerStatus().Running {
		t.Fatal("listeners started without the preference set")
	}

	a.SetAutoStartListeners(true)
	a.bg.autoStarted = false
	a.autoStart()
	if !a.GetServerStatus().Running {
		t.Fatal("listeners did not start with the preference set")
	}
	if !a.GetBackgroundSettings().AutoStartListeners {
		t.Error("the preference does not read back")
	}
}

// A failure on launch happens before the window has loaded, so it is kept
// until the window asks — once.
func TestAutoStart_AFailureIsReportedOnce(t *testing.T) {
	cfg := udpConfig(t)
	busy, err := net.ListenPacket("udp", net.JoinHostPort(cfg.BindAddress, strconv.Itoa(cfg.UDPPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	a := openApp(t)
	a.SaveServerConfig(cfg)
	a.SetAutoStartListeners(true)
	a.autoStart()

	msg := a.GetAutoStartError()
	if msg == "" {
		t.Fatal("a port in use did not produce an error")
	}
	if a.GetAutoStartError() != "" {
		t.Error("the error was reported twice")
	}
}

// A second engine on the same directory is refused, and the window can say
// why instead of receiving into someone else's database.
func TestDataDirConflict(t *testing.T) {
	dir := t.TempDir()
	first := newAppIn(storage.NewConfigStoreAt(dir))
	if err := first.engine.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	defer first.engine.Close()

	second := newAppIn(storage.NewConfigStoreAt(dir))
	_ = second.engine.Open(event.NewMockEventEmitter())
	defer second.engine.Close()

	if !strings.Contains(second.GetDataDirConflict(), "already using") {
		t.Fatalf("conflict not reported: %q", second.GetDataDirConflict())
	}
	if err := second.StartServer(udpConfig(t)); err == nil {
		t.Fatal("the second engine started receiving into the first one's directory")
	}
	if first.GetDataDirConflict() != "" {
		t.Error("the first engine reports a conflict it does not have")
	}
}
