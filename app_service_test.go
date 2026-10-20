package main

import (
	"net"
	"testing"
	"time"

	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/remote"
	"SyslogStudio/internal/storage"
)

// fakeService serves an engine of its own, as the system service would, and
// returns a window's connection to it.
func fakeService(t *testing.T, udpPort int) (*engine.Engine, *remote.Server, *remote.Client) {
	t.Helper()
	eng := engine.New(storage.NewConfigStoreAt(t.TempDir()))
	cfg := eng.GetDefaultConfig()
	cfg.UDPPort = udpPort
	eng.SaveServerConfig(cfg)
	srv := remote.NewServer(eng, "", nil)
	if err := eng.Open(srv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		srv.Close()
		eng.Close()
	})
	window, service := net.Pipe()
	go srv.ServeConn(service)
	c, err := remote.NewClient(window, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return eng, srv, c
}

// The window drives the service while connected to it: its settings are the
// service's. When the service goes, the window drives its own engine again.
func TestApp_DrivesTheServiceThenItsOwnEngine(t *testing.T) {
	a := newAppIn(storage.NewConfigStoreAt(t.TempDir()))
	own := a.GetDefaultConfig()
	own.UDPPort = 1514
	a.SaveServerConfig(own)
	a.openLocal()
	t.Cleanup(a.stopLink)

	_, srv, c := fakeService(t, 514)
	a.useService(c, false)
	if !a.drivingService() || a.local() != nil {
		t.Fatal("the window still drives its own engine")
	}
	if got := a.GetDefaultConfig().UDPPort; got != 514 {
		t.Fatalf("the window shows port %d, the service's is 514", got)
	}
	if link := a.GetServiceLink(); link.Mode != linkService {
		t.Fatalf("link: %+v", link)
	}
	if _, ok := a.keyMaterial().(*remote.Client); !ok {
		t.Fatal("certificate exports would come from the window's own engine")
	}

	// The window stops the service itself: the connection it loses is not
	// coming back, and it goes straight to its own engine.
	a.link.mu.Lock()
	a.link.lettingGo = true
	a.link.mu.Unlock()
	srv.Close()
	select {
	case <-c.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the connection was not lost")
	}
	a.reconnect(c)

	if a.drivingService() || a.local() == nil {
		t.Fatal("the window did not go back to its own engine")
	}
	if got := a.GetDefaultConfig().UDPPort; got != 1514 {
		t.Fatalf("the window's own engine shows port %d, want 1514", got)
	}
	if link := a.GetServiceLink(); link.Mode != linkLocal {
		t.Fatalf("link: %+v", link)
	}
}

// Installing the service from a window that drives it would hand the service
// its own settings back, or worse, the window's.
func TestApp_InstallRefusedWhileDrivingTheService(t *testing.T) {
	a := newAppIn(storage.NewConfigStoreAt(t.TempDir()))
	a.openLocal()
	t.Cleanup(a.stopLink)
	_, _, c := fakeService(t, 514)
	a.useService(c, false)
	if _, err := a.keyMaterial().ExportBundle(); err == nil {
		t.Fatal("a bundle was exported from the service's own settings")
	}
}
