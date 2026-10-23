package engine

// Backup destinations: where copies go, with their credentials kept as a
// routing destination's are — write-only, encrypted with the database, and
// bound to the server they were given for.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"SyslogStudio/internal/backup"
	"SyslogStudio/internal/models"
)

const (
	// listTimeout bounds asking a destination what it holds.
	listTimeout = 30 * time.Second
	// testTimeout bounds testing one.
	testTimeout = 60 * time.Second
)

func sortStrings(s []string) { sort.Strings(s) }

func (e *Engine) destination(id string) (models.BackupDestination, bool) {
	for _, d := range e.loadBackupConfig().Destinations {
		if d.ID == id {
			return d, true
		}
	}
	return models.BackupDestination{}, false
}

// accessFor is what signs in to d, from the secret store.
func (e *Engine) accessFor(d models.BackupDestination) models.BackupAccess {
	var a models.BackupAccess
	if e.secretStore == nil || !backup.NeedsSecret(d) {
		return a
	}
	if blob := e.secretStore.Get(d.ID, backup.AccessKey(d)); blob != "" {
		json.Unmarshal([]byte(blob), &a)
	}
	return a
}

// forDisplay is d as the window sees it: no credential, only whether one is
// on file for where it points.
func (e *Engine) forDisplay(d models.BackupDestination) models.BackupDestination {
	a := e.accessFor(d)
	d.Secret, d.Passphrase = "", ""
	d.HasSecret = a.Password != "" || a.Key != ""
	return d
}

// formAccess is what signs in to d as the form gives it, completed with
// what is on file for the same server: the form never sees a stored secret,
// so a field left empty means "keep it".
func (e *Engine) formAccess(d models.BackupDestination) models.BackupAccess {
	stored := models.BackupAccess{}
	if d.ID != "" {
		stored = e.accessFor(d)
	}
	a := stored
	if d.Secret != "" {
		if d.Auth == models.SFTPKey && d.Kind == models.BackupToSFTP {
			a.Key, a.Passphrase = d.Secret, d.Passphrase
		} else {
			a.Password = d.Secret
		}
	} else if d.Passphrase != "" {
		a.Passphrase = d.Passphrase
	}
	return a
}

// SaveBackupDestination adds or changes a destination. A server must have
// been tested, and its identity trusted, before it is saved: a backup at
// three in the morning has nobody to ask.
func (e *Engine) SaveBackupDestination(d models.BackupDestination) (models.BackupDestination, error) {
	d.Name = strings.TrimSpace(d.Name)
	d.Host = strings.TrimSpace(d.Host)
	if err := backup.Validate(d); err != nil {
		return models.BackupDestination{}, err
	}
	if d.Kind == models.BackupToFolder {
		d.Path = filepath.Clean(d.Path)
		if err := checkWritable(d.Path); err != nil {
			return models.BackupDestination{}, fmt.Errorf("the backups cannot be written to %s: %w", d.Path, err)
		}
	}
	if d.Kind == models.BackupToSFTP && d.HostKey == "" {
		return models.BackupDestination{}, errors.New("test the connection first, to see and trust the server's key")
	}
	isNew := d.ID == ""
	if isNew {
		d.ID = newID("dest")
	}
	if d.Name == "" {
		d.Name = d.Host
		if d.Kind == models.BackupToFolder {
			d.Name = filepath.Base(d.Path)
		}
	}

	if backup.NeedsSecret(d) {
		a := e.formAccess(d)
		if d.Kind == models.BackupToSFTP && d.Auth == models.SFTPKey && a.Key == "" {
			return models.BackupDestination{}, errors.New("choose the private key")
		}
		if (d.Kind != models.BackupToSFTP || d.Auth == models.SFTPPassword) && a.Password == "" {
			return models.BackupDestination{}, errors.New("the password is missing")
		}
		blob, _ := json.Marshal(a)
		if e.secretStore == nil {
			return models.BackupDestination{}, errors.New("there is nowhere to keep the credential")
		}
		if err := e.secretStore.Set(d.ID, backup.AccessKey(d), string(blob)); err != nil {
			return models.BackupDestination{}, fmt.Errorf("store the credential: %w", err)
		}
	} else if e.secretStore != nil && !isNew {
		e.secretStore.Delete(d.ID)
	}
	d.Secret, d.Passphrase, d.HasSecret = "", "", false

	cfg := e.loadBackupConfig()
	found := false
	for i := range cfg.Destinations {
		if cfg.Destinations[i].ID == d.ID {
			cfg.Destinations[i], found = d, true
		}
	}
	if !found {
		cfg.Destinations = append(cfg.Destinations, d)
		// From the next scheduled run on, not at once: "Back up now" is
		// there for that.
		e.updateBackupState(func(st *backupState) {
			st.Destinations[d.ID] = destState{Since: time.Now().Format(time.RFC3339)}
		})
	}
	e.configStore.SaveBackup(cfg)
	e.emitBackupStatus()
	return e.forDisplay(d), nil
}

// DeleteBackupDestination removes a destination and its credential. The
// copies it holds stay where they are.
func (e *Engine) DeleteBackupDestination(id string) error {
	cfg := e.loadBackupConfig()
	kept := cfg.Destinations[:0]
	for _, d := range cfg.Destinations {
		if d.ID != id {
			kept = append(kept, d)
		}
	}
	cfg.Destinations = kept
	if len(kept) == 0 {
		cfg.Enabled = false
	}
	e.configStore.SaveBackup(cfg)
	if e.secretStore != nil {
		e.secretStore.Delete(id)
	}
	e.updateBackupState(func(st *backupState) { delete(st.Destinations, id) })
	e.emitBackupStatus()
	return nil
}

// TestBackupDestination connects to d as the form has it, writes a file,
// lists, and removes it. A server met for the first time answers with its
// fingerprint, for the user to trust.
func (e *Engine) TestBackupDestination(d models.BackupDestination) models.BackupDestinationCheck {
	if err := backup.Validate(d); err != nil {
		return models.BackupDestinationCheck{Error: err.Error()}
	}
	ctx, cancel := context.WithTimeout(context.Background(), testTimeout)
	defer cancel()
	t, err := backup.Connect(ctx, d, e.formAccess(d))
	var unknown *backup.UnknownServerError
	var changed *backup.ChangedServerError
	switch {
	case errors.As(err, &unknown):
		return models.BackupDestinationCheck{Unknown: true, Fingerprint: unknown.Fingerprint, Detail: unknown.Detail}
	case errors.As(err, &changed):
		return models.BackupDestinationCheck{Changed: true, Fingerprint: changed.Fingerprint, Detail: changed.Detail,
			Error: changed.Error()}
	case err != nil:
		return models.BackupDestinationCheck{Error: err.Error()}
	}
	defer t.Close()
	probe := fmt.Sprintf("syslogstudio-test-%d.tmp", time.Now().UnixNano())
	if err := t.Put(probe, strings.NewReader("SyslogStudio checks that it can write here.\n")); err != nil {
		return models.BackupDestinationCheck{Error: "connected, but writing failed: " + err.Error()}
	}
	if _, err := t.List(); err != nil {
		t.Remove(probe)
		return models.BackupDestinationCheck{Error: "connected, but listing failed: " + err.Error()}
	}
	if err := t.Remove(probe); err != nil {
		return models.BackupDestinationCheck{Error: "connected, but deleting failed: " + err.Error()}
	}
	return models.BackupDestinationCheck{OK: true}
}

// BackupDestinationAccess hands a destination and what signs in to it to
// the window, which reads a backup itself. On Host only: never bound to the
// interface.
func (e *Engine) BackupDestinationAccess(id string) (models.BackupDestination, models.BackupAccess, error) {
	d, ok := e.destination(id)
	if !ok {
		return models.BackupDestination{}, models.BackupAccess{}, fmt.Errorf("no such destination: %s", id)
	}
	a := e.accessFor(d)
	d.Secret, d.Passphrase = "", ""
	return d, a, nil
}

// backupSecretIDs are the destinations whose credentials the secret store
// keeps: pruning it for the routing must not take them.
func (e *Engine) backupSecretIDs(keep map[string]bool) {
	for _, d := range e.loadBackupConfig().Destinations {
		keep[d.ID] = true
	}
}

// ListBackups lists the copies at every destination, and those made before
// a restore, newest first; destinations that do not answer are said so.
func (e *Engine) ListBackups() models.BackupListing {
	cfg := e.loadBackupConfig()
	made := e.loadBackupState().Made
	var mu sync.Mutex
	// Never null: the window lists what it gets.
	out := models.BackupListing{Files: []models.BackupFile{}}
	var wg sync.WaitGroup
	for _, d := range cfg.Destinations {
		wg.Add(1)
		go func(d models.BackupDestination) {
			defer wg.Done()
			files, err := e.listAt(d, made)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				out.Problems = append(out.Problems, models.BackupProblem{Destination: d.ID, Name: d.Name, Error: err.Error()})
				return
			}
			out.Files = append(out.Files, files...)
		}(d)
	}
	wg.Wait()
	safety := models.BackupDestination{Kind: models.BackupToFolder, Path: filepath.Join(e.DataDir(), safetyDir)}
	if files, err := e.listAt(safety, made); err == nil {
		for i := range files {
			files[i].Destination, files[i].DestinationName = "", ""
		}
		out.Files = append(out.Files, files...)
	}
	// By the instant: a header says it in UTC, a name in local time.
	sort.SliceStable(out.Files, func(i, j int) bool {
		return parseTime(out.Files[i].Created).After(parseTime(out.Files[j].Created))
	})
	return out
}

func (e *Engine) listAt(d models.BackupDestination, made map[string]madeInfo) ([]models.BackupFile, error) {
	ctx, cancel := context.WithTimeout(context.Background(), listTimeout)
	defer cancel()
	t, err := backup.Connect(ctx, d, e.accessFor(d))
	if err != nil {
		return nil, describeConnectError(d, err)
	}
	defer t.Close()
	files, err := backup.List(t)
	if err != nil {
		return nil, err
	}
	for i := range files {
		f := &files[i]
		f.Destination, f.DestinationName = d.ID, d.Name
		if d.Kind == models.BackupToFolder {
			f.Path = filepath.Join(d.Path, f.Name)
			if described, err := backup.Describe(f.Path); err == nil {
				described.Destination, described.DestinationName = d.ID, d.Name
				*f = described
				continue
			}
		}
		if m, ok := made[f.Name]; ok {
			f.Lock, f.KeyID, f.App = m.Lock, m.KeyID, m.App
		}
	}
	return files, nil
}

func checkWritable(dir string) error {
	t, err := backup.Connect(context.Background(), models.BackupDestination{Kind: models.BackupToFolder, Path: dir}, models.BackupAccess{})
	if err != nil {
		return err
	}
	defer t.Close()
	probe := fmt.Sprintf(".syslogstudio-check-%d", time.Now().UnixNano())
	if err := t.Put(probe, strings.NewReader("")); err != nil {
		return err
	}
	if err := t.Remove(probe); err != nil {
		slog.Warn("could not remove the write check", "dir", dir, "error", err)
	}
	return nil
}
