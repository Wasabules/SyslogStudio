// Package backup makes copies of the database, sends them where the user
// said — folders and servers — and opens them again.
//
// A copy is encrypted the way the database is, here, before it goes
// anywhere: in the vault format, with the master secret, and carrying its own
// locks — the password's and the recovery key's — so that it opens on its
// own, on another machine, after the installation is gone. A server only ever
// stores what it cannot read. A database that is not encrypted is copied
// locked to the recovery key alone if there is one, in the clear otherwise.
//
// Only files named like the copies made here are listed, and only those are
// ever deleted: a folder or a server may hold anything else.
package backup

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	// partExt is a copy on its way: renamed once whole.
	partExt = ".part"
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

// IsName says whether name is that of a copy made here.
func IsName(name string) bool {
	_, _, ok := parseName(name)
	return ok
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

// Seal makes the copy of the database snapshot at src: dst, a file on this
// machine, locked with lock, and read back — a copy that would not open is
// not sent anywhere as if it would. dst appears whole or not at all.
func Seal(src, dst string, lock Lock, app string, encrypt, verify Progress) error {
	size := fileSize(src)
	if lock.Master == "" {
		return copyFile(src, dst, scaled(encrypt, size))
	}
	h := vault.Header{Kind: vault.KindBackup, Slots: lock.Slots, App: app}
	if err := vault.EncryptFile(src, dst, lock.Master, h, scaled(encrypt, size)); err != nil {
		return err
	}
	if _, err := vault.Verify(dst, lock.Master, scaled(verify, size)); err != nil {
		os.Remove(dst)
		return fmt.Errorf("the backup did not read back: %w", err)
	}
	return nil
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
	f := fromName(filepath.Base(path), fi.Size(), fi.ModTime())
	f.Path = path
	in, err := os.Open(path)
	if err != nil {
		return f, err
	}
	defer in.Close()
	return describe(f, vault.PeekReader(in))
}

// describe fills in what opens the copy br starts, from its header, leaving
// br where it was.
func describe(f models.BackupFile, br *bufio.Reader) (models.BackupFile, error) {
	if h, err := vault.PeekHeader(br); err == nil {
		if h.Kind != vault.KindBackup {
			return f, ErrNotBackup
		}
		f.Lock, f.KeyID, f.App = lockKind(true, h.Slots), keyID(h.Slots), h.App
		if h.Created != "" {
			f.Created = h.Created
		}
		return f, nil
	} else if !errors.Is(err, vault.ErrNotVault) {
		return f, err
	}
	head, err := br.Peek(16)
	if err != nil || string(head) != "SQLite format 3\x00" {
		return f, ErrNotBackup
	}
	f.Lock = models.BackupLockNone
	return f, nil
}

// fromName is what a copy's name and size say about it.
func fromName(name string, size int64, modTime time.Time) models.BackupFile {
	f := models.BackupFile{Name: name, SizeMB: float64(size) / (1 << 20), Lock: models.BackupLockUnknown}
	if at, safety, ok := parseName(name); ok {
		f.Created, f.SafetyCopy = at.Format(time.RFC3339), safety
	} else if !modTime.IsZero() {
		f.Created = modTime.Format(time.RFC3339)
	}
	return f
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
	in, err := os.Open(path)
	if err != nil {
		return f, err
	}
	defer in.Close()
	_, err = Unseal(in, fileSize(path), cred, dst, progress)
	return f, err
}

// Unseal writes the database the copy read from r holds to dst, a plain
// SQLite file, which appears only once all of it has authenticated: a copy
// can be opened as it arrives from a server. size, if known, drives
// progress. It says what opened the copy.
func Unseal(r io.Reader, size int64, cred Credentials, dst string, progress Progress) (models.BackupFile, error) {
	br := vault.PeekReader(r)
	f, err := describe(models.BackupFile{}, br)
	if err != nil {
		return f, err
	}
	if f.Lock == models.BackupLockNone {
		return f, vault.WriteAtomically(dst, func(w io.Writer) error {
			_, err := io.Copy(w, &progressReader{r: br, progress: scaled(progress, size)})
			return err
		})
	}
	h, err := vault.PeekHeader(br)
	if err != nil {
		return f, err
	}
	master, err := unlock(h.Slots, cred)
	if err != nil {
		return f, err
	}
	return f, vault.WriteAtomically(dst, func(w io.Writer) error {
		_, err := vault.Decrypt(w, br, master, scaled(progress, size))
		return err
	})
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

// DescribeName is what a copy's name alone says about it: when it was made.
func DescribeName(name string) (models.BackupFile, error) {
	if !IsName(name) {
		return models.BackupFile{}, ErrNotBackup
	}
	return fromName(name, 0, time.Time{}), nil
}
