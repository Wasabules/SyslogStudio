package engine

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
)

const inboxPassword = "correct horse battery"

// encryptedDesk is the window's own engine with at-rest encryption on and the
// database open.
func encryptedDesk(t *testing.T, dir string) *Engine {
	t.Helper()
	desk := New(storage.NewConfigStoreAt(dir))
	if err := desk.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	if err := desk.EnableEncryption(inboxPassword); err != nil {
		t.Fatal(err)
	}
	return desk
}

// sealingService is a service installed by desk, keeping its encryption.
func sealingService(t *testing.T, desk *Engine) *Engine {
	t.Helper()
	pub, err := desk.PrepareInbox()
	if err != nil {
		t.Fatal(err)
	}
	b, err := desk.ExportBundle()
	if err != nil {
		t.Fatal(err)
	}
	b.InboxPublicKey = pub
	svc := New(storage.NewConfigStoreAt(t.TempDir()))
	if err := svc.ImportBundle(b); err != nil {
		t.Fatal(err)
	}
	return svc
}

func received(n int, text string) []models.SyslogMessage {
	out := make([]models.SyslogMessage, n)
	now := time.Now()
	for i := range out {
		out[i] = models.SyslogMessage{
			ID:         fmt.Sprintf("%s-%d-%d", text, now.UnixNano(), i),
			Hostname:   "fw-01",
			Message:    fmt.Sprintf("%s %d", text, i),
			Timestamp:  now,
			ReceivedAt: now.Add(time.Duration(i) * time.Millisecond),
		}
	}
	return out
}

// collect does what the window does: list, open, store, acknowledge.
func collect(t *testing.T, svc, desk *Engine) int {
	t.Helper()
	list, err := svc.InboxBatches()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, b := range list {
		data, err := svc.InboxBatch(b.ID)
		if err != nil {
			t.Fatal(err)
		}
		msgs, err := desk.OpenInboxBatch(data)
		if err != nil {
			t.Fatal(err)
		}
		if err := desk.StoreCollected(msgs); err != nil {
			t.Fatal(err)
		}
		if err := svc.InboxAck(b.ID); err != nil {
			t.Fatal(err)
		}
		n += len(msgs)
	}
	return n
}

func storedTexts(e *Engine) []string {
	var out []string
	for _, m := range e.QueryMessages(models.QueryOptions{Page: 1, PageSize: 1000}).Messages {
		out = append(out, m.Message)
	}
	return out
}

// The whole point: a service keeps receiving for an encrypted database
// without the password, stores nothing readable, and the window moves what it
// received into the encrypted database once unlocked.
func TestInbox_ServiceSealsWindowCollects(t *testing.T) {
	desk := encryptedDesk(t, t.TempDir())
	defer desk.Close()
	svc := sealingService(t, desk)
	if err := svc.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	if svc.logStore != nil {
		t.Fatal("a sealing service opened a database")
	}
	if st := svc.GetInboxStatus(); !st.Sealed || st.KeyID == "" {
		t.Fatalf("inbox status: %+v", st)
	}
	if err := svc.ImportMessages(received(3, "sealed by the service"), true); err != nil {
		t.Fatal(err)
	}
	svc.Close()

	// Nothing in the service's directory reads in the clear.
	filepath.WalkDir(svc.DataDir(), func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, _ := os.ReadFile(path)
		if strings.Contains(string(data), "sealed by the service") {
			t.Errorf("%s holds a message in the clear", path)
		}
		return nil
	})

	if n := collect(t, svc, desk); n != 3 {
		t.Fatalf("collected %d messages, want 3", n)
	}
	if got := storedTexts(desk); len(got) != 3 {
		t.Fatalf("the window's database holds %v", got)
	}
	if st := svc.GetInboxStatus(); st.Batches != 0 {
		t.Fatalf("batches left after collecting: %+v", st)
	}
}

// The key survives the window: the next unlock loads it, and batches sealed
// meanwhile open.
func TestInbox_KeyComesBackWithTheUnlock(t *testing.T) {
	dir := t.TempDir()
	desk := encryptedDesk(t, dir)
	svc := sealingService(t, desk)
	pub, _ := desk.PrepareInbox()
	desk.Close()

	again := New(storage.NewConfigStoreAt(dir))
	if err := again.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if again.HasInboxKey() {
		t.Fatal("the inbox key was readable before the unlock")
	}
	if err := again.UnlockDatabase(inboxPassword); err != nil {
		t.Fatal(err)
	}
	if !again.HasInboxKey() {
		t.Fatal("the unlock did not load the inbox key")
	}
	if got, _ := again.PrepareInbox(); string(got) != string(pub) {
		t.Fatal("a second key was made: batches sealed for the first would no longer open")
	}

	if err := svc.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	svc.ImportMessages(received(2, "while the window was closed"), true)
	svc.Close()
	if n := collect(t, svc, again); n != 2 {
		t.Fatalf("collected %d, want 2", n)
	}
}

func TestInbox_KeyNeedsEncryption(t *testing.T) {
	desk := New(storage.NewConfigStoreAt(t.TempDir()))
	if _, err := desk.PrepareInbox(); err == nil || !strings.Contains(err.Error(), "encryption") {
		t.Fatalf("an inbox key without encryption: %v", err)
	}
}

// A service that stored in the clear before it was told to seal moves its
// database into the inbox and deletes it.
func TestInbox_ClearDatabaseIsMovedIn(t *testing.T) {
	desk := encryptedDesk(t, t.TempDir())
	defer desk.Close()
	svc := sealingService(t, desk)

	inbox := svc.configStore.LoadInbox()
	svc.configStore.SaveInbox(nil)
	if err := svc.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	if err := svc.logStore.InsertMessages(received(2500, "stored in the clear")); err != nil {
		t.Fatal(err)
	}
	svc.Close()
	dbPath := storage.DBPathIn(svc.DataDir())
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatal(err)
	}

	svc2 := New(storage.NewConfigStoreAt(svc.DataDir()))
	svc2.configStore.SaveInbox(inbox)
	if err := svc2.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the clear database was not moved in")
		}
		time.Sleep(50 * time.Millisecond)
	}
	svc2.Close()
	if n := collect(t, svc2, desk); n != 2500 {
		t.Fatalf("collected %d of the 2500 stored in the clear", n)
	}
}

// A service that stored in the clear is told to seal by the administrator
// step (sysvc.Seal): stopped, SealFor, started. Its configuration stays as
// it was, its quota with it, and the history it had reaches the window's
// encrypted database through the inbox.
func TestSealFor_MovesTheClearServiceIntoTheInbox(t *testing.T) {
	desk := encryptedDesk(t, t.TempDir())
	defer desk.Close()
	pub, err := desk.PrepareInbox()
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	svc := New(storage.NewConfigStoreAt(dir))
	if err := svc.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	cfg := svc.GetDefaultConfig()
	cfg.UDPPort = 5514
	svc.SaveServerConfig(cfg)
	if err := svc.logStore.InsertMessages(received(320, "kept in the clear")); err != nil {
		t.Fatal(err)
	}
	svc.Close()
	svc.configStore.SaveInbox(&models.InboxConfig{QuotaBytes: 5 << 20})

	stopped := New(storage.NewConfigStoreAt(dir))
	if err := stopped.SealFor([]byte("not a key")); err == nil {
		t.Fatal("sealed for something that is not a key")
	}
	if err := stopped.SealFor(pub); err != nil {
		t.Fatal(err)
	}
	if got := stopped.configStore.LoadInbox(); got == nil || got.QuotaBytes != 5<<20 {
		t.Fatalf("the inbox configuration: %+v", got)
	}

	sealed := New(storage.NewConfigStoreAt(dir))
	if err := sealed.Open(event.NewMockEventEmitter()); err != nil {
		t.Fatal(err)
	}
	if got := sealed.GetDefaultConfig().UDPPort; got != 5514 {
		t.Fatalf("sealing changed the listeners: UDP port %d", got)
	}
	dbPath := storage.DBPathIn(dir)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the clear database was not moved into the inbox")
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !sealed.GetInboxStatus().Sealed {
		t.Fatal("the service does not seal")
	}
	if n := collect(t, sealed, desk); n != 320 {
		t.Fatalf("collected %d of the 320 kept in the clear", n)
	}
	sealed.Close()
}
