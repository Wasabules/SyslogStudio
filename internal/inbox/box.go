package inbox

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"SyslogStudio/internal/models"
)

// DirName is the inbox's directory, inside the service's data directory.
const DirName = "inbox"

const ext = ".sealed"

// idPattern is what a batch is named: when it was sealed, then a sequence
// number, so names sort in the order the batches were written. A window
// names the batch it wants; anything else — a path, above all — is refused.
var idPattern = regexp.MustCompile(`^[0-9]{20}-[0-9]{6}$`)

// ErrBadID is a batch name that is not one.
var ErrBadID = errors.New("not an inbox batch name")

// Box is the directory sealed batches wait in.
type Box struct{ Dir string }

func (b Box) path(id string) (string, error) {
	if !idPattern.MatchString(id) {
		return "", ErrBadID
	}
	return filepath.Join(b.Dir, id+ext), nil
}

// List returns the batches waiting, oldest first.
func (b Box) List() ([]models.InboxBatch, error) {
	entries, err := os.ReadDir(b.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []models.InboxBatch
	for _, e := range entries {
		id, ok := strings.CutSuffix(e.Name(), ext)
		if !ok || !idPattern.MatchString(id) || !e.Type().IsRegular() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, models.InboxBatch{ID: id, Bytes: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// Read returns a batch's sealed bytes.
func (b Box) Read(id string) ([]byte, error) {
	p, err := b.path(id)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(p)
}

// Remove deletes a batch, and returns its size. A batch already gone is not
// an error: two windows collecting at once both ask.
func (b Box) Remove(id string) (int64, error) {
	p, err := b.path(id)
	if err != nil {
		return 0, err
	}
	info, err := os.Stat(p)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	return info.Size(), nil
}

// write stores a batch under id, through a temporary file so a reader never
// meets half of one.
func (b Box) write(id string, data []byte) error {
	p, err := b.path(id)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(b.Dir, 0700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmp)
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("store the batch: %w", err)
	}
	return nil
}
