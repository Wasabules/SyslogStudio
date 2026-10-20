package main

import (
	"fmt"
	"net"
	"testing"
	"time"

	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/remote"
	"SyslogStudio/internal/storage"
)

const sealedPassword = "correct horse battery"

// sealingService is a service sealing for the key of the encrypted database
// in deskDir, and a window's connection to it.
func sealingService(t *testing.T, deskDir string) (*engine.Engine, *remote.Server, *remote.Client) {
	t.Helper()
	desk := engine.New(storage.NewConfigStoreAt(deskDir))
	if err := desk.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	if err := desk.EnableEncryption(sealedPassword); err != nil {
		t.Fatal(err)
	}
	pub, err := desk.PrepareInbox()
	if err != nil {
		t.Fatal(err)
	}
	desk.Close()

	cs := storage.NewConfigStoreAt(t.TempDir())
	cs.SaveInbox(&models.InboxConfig{PublicKey: pub})
	svc := engine.New(cs)
	srv := remote.NewServer(svc, "", nil)
	if err := svc.Open(srv); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		srv.Close()
		svc.Close()
	})
	window, service := net.Pipe()
	go srv.ServeConn(service)
	c, err := remote.NewClient(window, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	return svc, srv, c
}

func batchOf(n int) []models.SyslogMessage {
	out := make([]models.SyslogMessage, n)
	now := time.Now()
	for i := range out {
		out[i] = models.SyslogMessage{
			ID:         fmt.Sprintf("sealed-%d-%d", now.UnixNano(), i),
			Hostname:   "fw-01",
			Message:    fmt.Sprintf("denied %d", i),
			Timestamp:  now,
			ReceivedAt: now,
		}
	}
	return out
}

// Driving a service that seals, the window keeps its own encrypted database
// for the history, and fills it from the service's inbox once unlocked.
func TestApp_CollectsWhatASealingServiceReceived(t *testing.T) {
	deskDir := t.TempDir()
	svc, srv, c := sealingService(t, deskDir)

	a := newAppIn(storage.NewConfigStoreAt(deskDir))
	t.Cleanup(a.stopLink)
	a.useService(c, false)

	if link := a.GetServiceLink(); link.Mode != linkService || !link.Sealed {
		t.Fatalf("link: %+v", link)
	}
	if !a.IsEncryptionLocked() {
		t.Fatal("the history is not the window's encrypted database")
	}
	if a.local() != nil {
		t.Fatal("the window's own engine counts as driven while the service is")
	}

	// A full batch is sealed at once.
	if err := svc.ImportMessages(batchOf(2000), true); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, "a sealed batch", func() bool {
		list, _ := c.InboxBatches()
		return len(list) > 0
	})

	a.collectInbox()
	if n := a.QueryMessages(models.QueryOptions{Page: 1, PageSize: 10}).Total; n != 0 {
		t.Fatalf("collected %d messages before the unlock", n)
	}

	if err := a.UnlockDatabase(sealedPassword); err != nil {
		t.Fatal(err)
	}
	a.collectInbox()
	if n := a.QueryMessages(models.QueryOptions{Page: 1, PageSize: 10}).Total; n != 2000 {
		t.Fatalf("the window's database holds %d messages, want 2000", n)
	}
	if st := c.GetInboxStatus(); st.Batches != 0 {
		t.Fatalf("batches left in the service: %+v", st)
	}

	// The service goes: the window drives its own engine, the same one, its
	// database still open.
	a.link.mu.Lock()
	a.link.lettingGo = true
	a.link.mu.Unlock()
	srv.Close()
	<-c.Done()
	a.reconnect(c)
	if a.drivingService() || a.local() == nil {
		t.Fatal("the window did not go back to its own engine")
	}
	if a.IsEncryptionLocked() {
		t.Fatal("going back to its own engine locked the database again")
	}
	if n := a.QueryMessages(models.QueryOptions{Page: 1, PageSize: 10}).Total; n != 2000 {
		t.Fatalf("after going back: %d messages", n)
	}
}

func waitUntil(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
