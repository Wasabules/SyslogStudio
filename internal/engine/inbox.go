package engine

// The sealed inbox, from both ends (see package inbox).
//
// A service told to seal keeps no database: what it receives goes into
// sealed batches in its inbox, which windows list, fetch and acknowledge.
// The window that installed it holds the private key, behind its database
// password, opens the batches and stores the messages in its own encrypted
// database.

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"SyslogStudio/internal/inbox"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/storage"
)

// inboxListLimit bounds how many batches one listing returns: the oldest,
// which are collected first.
const inboxListLimit = 200

// migrateBatch is how many messages of a database left from before sealing
// go into each batch.
const migrateBatch = 1000

func (e *Engine) inboxBox() inbox.Box {
	return inbox.Box{Dir: filepath.Join(e.DataDir(), inbox.DirName)}
}

// openInbox starts sealing, when this engine is configured to. It reports
// whether it is: a sealing engine opens no database, whatever happens here.
func (e *Engine) openInbox() bool {
	cfg := e.configStore.LoadInbox()
	if cfg == nil {
		return false
	}
	w, err := inbox.NewWriter(e.inboxBox().Dir, *cfg, slog.Default(), func() {
		if e.emitter != nil {
			e.emitter.Emit("inbox:batch")
		}
	})
	if err != nil {
		// Not a reason to store in the clear what was meant to be sealed.
		e.inboxErr = fmt.Errorf("the sealed inbox cannot be used, so nothing received is stored: %w", err)
		slog.Error("sealed inbox", "error", e.inboxErr)
		return true
	}
	e.inbox = w
	e.server.SetInbox(w)

	// A database left from before sealing is moved into the inbox, then
	// deleted: sealing means nothing received rests in the clear.
	if path := storage.DBPathIn(e.DataDir()); fileExists(path) {
		go e.migrateToInbox(path)
	}
	return true
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// migrateToInbox empties the database at path into the inbox, oldest first,
// then deletes it. A batch is deleted from the database once sealed; stopped
// half way, the next start carries on, and a batch sealed twice is stored
// once, messages keeping their ids.
func (e *Engine) migrateToInbox(path string) {
	ls, err := storage.NewLogStore(models.StorageConfig{Enabled: true, Path: path}, nil)
	if err != nil {
		slog.Error("could not open the database to seal it", "error", err)
		return
	}
	ls.WaitReady()
	moved := 0
	for {
		msgs, err := ls.OldestMessages(migrateBatch)
		if err != nil {
			slog.Error("could not read the database to seal it", "error", err)
			ls.Close()
			return
		}
		if len(msgs) == 0 {
			break
		}
		if err := e.inbox.WriteNow(msgs); err != nil {
			slog.Error("could not seal the database", "error", err, "sealed", moved)
			ls.Close()
			return
		}
		ids := make([]string, len(msgs))
		for i, m := range msgs {
			ids[i] = m.ID
		}
		if err := ls.DeleteMessages(ids); err != nil {
			slog.Error("could not empty the database being sealed", "error", err)
			ls.Close()
			return
		}
		moved += len(msgs)
	}
	ls.Close()
	for _, p := range []string{path, path + "-wal", path + "-shm"} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			slog.Warn("could not delete the emptied database", "file", p, "error", err)
		}
	}
	slog.Info("moved the database into the sealed inbox", "messages", moved)
}

// GetInboxStatus says what this engine's inbox holds. Batches left from
// before sealing was turned off are counted too: a window still collects
// them.
func (e *Engine) GetInboxStatus() models.InboxStatus {
	if e.inbox != nil {
		return e.inbox.Status()
	}
	st := models.InboxStatus{Sealed: e.inboxErr != nil}
	if e.inboxErr != nil {
		st.Error = e.inboxErr.Error()
	}
	if list, err := e.inboxBox().List(); err == nil {
		st.Batches = len(list)
		for _, b := range list {
			st.Bytes += b.Bytes
		}
	}
	return st
}

// InboxBatches lists the batches waiting, oldest first. Asking is what tells
// the inbox a window is collecting.
func (e *Engine) InboxBatches() ([]models.InboxBatch, error) {
	if e.inbox != nil {
		e.inbox.MarkCollected()
	}
	list, err := e.inboxBox().List()
	if len(list) > inboxListLimit {
		list = list[:inboxListLimit]
	}
	return list, err
}

// InboxBatch returns one batch, sealed: only the window holding the key can
// read it.
func (e *Engine) InboxBatch(id string) ([]byte, error) {
	return e.inboxBox().Read(id)
}

// InboxAck deletes a batch the window has stored.
func (e *Engine) InboxAck(id string) error {
	if e.inbox != nil {
		return e.inbox.Remove(id)
	}
	_, err := e.inboxBox().Remove(id)
	return err
}

// --- The window's end -------------------------------------------------------

// PrepareInbox returns the public key a service seals for, creating the key
// pair the first time. The private key is kept with the CA's, encrypted by
// the database password, so the database must be encrypted and unlocked:
// sealing for a key kept in the clear would protect nothing.
func (e *Engine) PrepareInbox() ([]byte, error) {
	if !e.IsEncryptionEnabled() {
		return nil, fmt.Errorf("turn on at-rest encryption first: the inbox key is protected by its password")
	}
	if e.encryptionPassword == "" {
		return nil, fmt.Errorf("unlock the database first")
	}
	if e.inboxPriv == nil {
		if err := e.loadInboxKey(); err != nil {
			return nil, err
		}
	}
	if e.inboxPriv == nil {
		priv, pub, err := inbox.GenerateKey()
		if err != nil {
			return nil, err
		}
		if err := e.inboxKeyStore.Save(pub, priv, e.encryptionPassword); err != nil {
			return nil, fmt.Errorf("keep the inbox key: %w", err)
		}
		e.inboxPriv = priv
		slog.Info("created the sealed inbox key", "key", inbox.KeyID(pub))
	}
	return inbox.PublicKeyOf(e.inboxPriv)
}

// loadInboxKey reads the private key, if there is one, with the session
// password.
func (e *Engine) loadInboxKey() error {
	if !e.inboxKeyStore.Exists() {
		return nil
	}
	_, priv, err := e.inboxKeyStore.Load(e.encryptionPassword)
	if err != nil {
		return fmt.Errorf("read the inbox key: %w", err)
	}
	e.inboxPriv = priv
	return nil
}

// repersistInboxKey writes the key in memory again under the current
// password: encryption turned on or off, or its password changed.
func (e *Engine) repersistInboxKey() {
	if e.inboxPriv == nil || !e.canPersistKeys("inbox key") {
		return
	}
	pub, err := inbox.PublicKeyOf(e.inboxPriv)
	if err != nil {
		return
	}
	if err := e.inboxKeyStore.Save(pub, e.inboxPriv, e.encryptionPassword); err != nil {
		slog.Warn("failed to persist the inbox key", "error", err)
	}
}

// HasInboxKey reports whether this engine can open sealed batches now.
func (e *Engine) HasInboxKey() bool {
	return e.inboxPriv != nil
}

// OpenInboxBatch opens a batch sealed for this engine's key.
func (e *Engine) OpenInboxBatch(data []byte) ([]models.SyslogMessage, error) {
	if e.inboxPriv == nil {
		return nil, fmt.Errorf("the inbox key is not loaded: unlock the database first")
	}
	return inbox.Open(e.inboxPriv, data)
}

// StoreCollected writes collected messages to the database at once, and says
// whether they are there: only then may the service delete its copy.
func (e *Engine) StoreCollected(msgs []models.SyslogMessage) error {
	if e.logStore == nil || e.IsEncryptionLocked() {
		return fmt.Errorf("the database is not open")
	}
	return e.logStore.InsertMessages(msgs)
}
