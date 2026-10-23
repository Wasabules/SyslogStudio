// Package backup writes copies of the database to a folder of the user's
// choosing, lists them, and opens them again.
//
// A copy is encrypted the way the database is: in the vault format, with the
// master secret, and carrying its own locks — the password's and the
// recovery key's — so that it opens on its own, on another machine, after the
// installation is gone. A database that is not encrypted is copied locked to
// the recovery key alone if there is one, in the clear otherwise.
//
// Only files named like the copies made here are listed, and only those are
// ever deleted: the folder may hold anything else.
package backup

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/vault"
)

const (
	// Ext is an encrypted copy; PlainExt, one in the clear — an SQLite file.
	Ext      = ".ssbackup"
	PlainExt = ".db"

	prefix = "syslogstudio-"
	// safetySuffix marks the copy made just before a restore.
	safetySuffix = "-before-restore"
	stampLayout  = "20060102-150405"
)

// ErrWrongCredentials is a copy the password or key given does not open.
var ErrWrongCredentials = errors.New("this password or key does not open this backup")

// ErrNotBackup is a file that is not a copy made here.
var ErrNotBackup = errors.New("not a SyslogStudio backup")

// Lock is what a copy is locked with: a master secret and the locks that open
// it. A zero Lock is a copy in the clear.
type Lock struct {
	Master string
	Slots  []vault.Slot
}

// Kind is what opens a copy locked so (models.BackupLock*).
func (l Lock) Kind() string { return lockKind(l.Master != "", l.Slots) }

// KeyID names the recovery key that opens it, if one does.
func (l Lock) KeyID() string { return keyID(l.Slots) }

func lockKind(encrypted bool, slots []vault.Slot) string {
	if !encrypted {
		return models.BackupLockNone
	}
	var pw, key bool
	for _, s := range slots {
		pw = pw || s.Kind == vault.KindPassword
		key = key || s.Kind == vault.KindKey
	}
	switch {
	case pw && key:
		return models.BackupLockBoth
	case key:
		return models.BackupLockKey
	default:
		return models.BackupLockPassword
	}
}

func keyID(slots []vault.Slot) string {
	for _, s := range slots {
		if s.Kind == vault.KindKey {
			return s.KeyID
		}
	}
	return ""
}

// Name is the file name of a copy made at at.
func Name(at time.Time, safety, encrypted bool) string {
	name := prefix + at.Format(stampLayout)
	if safety {
		name += safetySuffix
	}
	if encrypted {
		return name + Ext
	}
	return name + PlainExt
}

// parseName says whether name is a copy made here, and when.
func parseName(name string) (at time.Time, safety, ok bool) {
	ext := filepath.Ext(name)
	if !strings.HasPrefix(name, prefix) || (ext != Ext && ext != PlainExt) {
		return time.Time{}, false, false
	}
	stem := strings.TrimSuffix(strings.TrimPrefix(name, prefix), ext)
	stem, safety = strings.CutSuffix(stem, safetySuffix)
	at, err := time.ParseInLocation(stampLayout, stem, time.Local)
	if err != nil {
		return time.Time{}, false, false
	}
	return at, safety, true
}

// Progress reports how far a step is, from 0 to 1.
type Progress func(fraction float64)

func scaled(p Progress, total int64) func(int64) {
	return func(done int64) {
		if p != nil && total > 0 {
			p(min(1, float64(done)/float64(total)))
		}
	}
}

// Write copies the database snapshot at src into dir, locked with lock, and
// reads it back: a copy that would not open is not left behind as if it
// would. The file appears whole or not at all. encrypt and verify report
// their progress.
func Write(src, dir string, at time.Time, safety bool, lock Lock, app string, encrypt, verify Progress) (models.BackupFile, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return models.BackupFile{}, err
	}
	size := fileSize(src)
	dst := filepath.Join(dir, Name(at, safety, lock.Master != ""))
	if _, err := os.Stat(dst); err == nil {
		return models.BackupFile{}, fmt.Errorf("%s already exists", filepath.Base(dst))
	}
	if lock.Master == "" {
		if err := copyFile(src, dst, scaled(encrypt, size)); err != nil {
			return models.BackupFile{}, err
		}
	} else {
		h := vault.Header{Kind: vault.KindBackup, Slots: lock.Slots, App: app}
		if err := vault.EncryptFile(src, dst, lock.Master, h, scaled(encrypt, size)); err != nil {
			return models.BackupFile{}, err
		}
		if _, err := vault.Verify(dst, lock.Master, scaled(verify, size)); err != nil {
			os.Remove(dst)
			return models.BackupFile{}, fmt.Errorf("the backup did not read back: %w", err)
		}
	}
	return Describe(dst)
}

func copyFile(src, dst string, progress func(int64)) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	return vault.WriteAtomically(dst, func(w io.Writer) error {
		_, err := io.Copy(w, &progressReader{r: in, progress: progress})
		return err
	})
}

type progressReader struct {
	r        io.Reader
	done     int64
	progress func(int64)
}

func (p *progressReader) Read(b []byte) (int, error) {
	n, err := p.r.Read(b)
	p.done += int64(n)
	if p.progress != nil && n > 0 {
		p.progress(p.done)
	}
	return n, err
}

func fileSize(path string) int64 {
	if fi, err := os.Stat(path); err == nil {
		return fi.Size()
	}
	return 0
}

// Describe says what the file at path is.
func Describe(path string) (models.BackupFile, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return models.BackupFile{}, err
	}
	at, safety, named := parseName(filepath.Base(path))
	f := models.BackupFile{
		Name: filepath.Base(path), Path: path, SizeMB: float64(fi.Size()) / (1 << 20),
		SafetyCopy: safety, Lock: models.BackupLockNone,
	}
	if named {
		f.Created = at.Format(time.RFC3339)
	} else {
		f.Created = fi.ModTime().Format(time.RFC3339)
	}
	if vault.IsVaultFile(path) {
		h, err := vault.ReadFileHeader(path)
		if err != nil {
			return f, err
		}
		if h.Kind != vault.KindBackup {
			return f, ErrNotBackup
		}
		f.Lock, f.KeyID, f.App = lockKind(true, h.Slots), keyID(h.Slots), h.App
		if h.Created != "" {
			f.Created = h.Created
		}
		return f, nil
	}
	if !isSQLite(path) {
		return f, ErrNotBackup
	}
	return f, nil
}

func isSQLite(path string) bool {
	in, err := os.Open(path)
	if err != nil {
		return false
	}
	defer in.Close()
	head := make([]byte, 16)
	_, err = io.ReadFull(in, head)
	return err == nil && string(head) == "SQLite format 3\x00"
}

// List lists the copies made here that dir holds, newest first.
func List(dir string) ([]models.BackupFile, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var out []models.BackupFile
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		if _, _, ok := parseName(ent.Name()); !ok {
			continue
		}
		if f, err := Describe(filepath.Join(dir, ent.Name())); err == nil {
			out = append(out, f)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name > out[j].Name })
	return out, nil
}

// Prune deletes the oldest of the scheduled and on-demand copies in dir
// beyond keep, and says which. The copies made before a restore are left to
// the user: they are what undoes it.
func Prune(dir string, keep int) ([]string, error) {
	if keep < 1 {
		keep = models.DefaultBackupKeep
	}
	files, err := List(dir)
	if err != nil {
		return nil, err
	}
	var removed []string
	kept := 0
	for _, f := range files {
		if f.SafetyCopy {
			continue
		}
		if kept < keep {
			kept++
			continue
		}
		if err := os.Remove(f.Path); err != nil {
			return removed, err
		}
		removed = append(removed, f.Name)
	}
	return removed, nil
}

// Credentials open a copy: its password, or the recovery key's file.
type Credentials struct {
	Password string
	KeyFile  []byte
}

// Open writes the database the copy at path holds to dst, a plain SQLite
// file, which appears only once all of it has authenticated.
func Open(path string, cred Credentials, dst string, progress Progress) (models.BackupFile, error) {
	f, err := Describe(path)
	if err != nil {
		return f, err
	}
	size := fileSize(path)
	if f.Lock == models.BackupLockNone {
		return f, copyFile(path, dst, scaled(progress, size))
	}
	h, err := vault.ReadFileHeader(path)
	if err != nil {
		return f, err
	}
	master, err := unlock(h.Slots, cred)
	if err != nil {
		return f, err
	}
	if _, err := vault.DecryptFile(path, dst, master, scaled(progress, size)); err != nil {
		return f, err
	}
	return f, nil
}

func unlock(slots []vault.Slot, cred Credentials) (string, error) {
	if len(cred.KeyFile) > 0 {
		priv, _, err := vault.ParseRecoveryKey(cred.KeyFile)
		if err != nil {
			return "", err
		}
		master, err := vault.OpenWithKey(slots, priv)
		if errors.Is(err, vault.ErrNoSlotForKey) {
			return "", fmt.Errorf("%w: it was not locked to this recovery key", ErrWrongCredentials)
		}
		return master, err
	}
	master, err := vault.OpenWithPassword(slots, cred.Password)
	if errors.Is(err, vault.ErrWrongPassword) {
		return "", ErrWrongCredentials
	}
	return master, err
}
