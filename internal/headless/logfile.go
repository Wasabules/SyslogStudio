package headless

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// LogFile is an io.Writer over a file that is rotated by size: a host left
// running for months must not fill the disk with its own diary.
type LogFile struct {
	path string
	max  int64
	keep int
	mu   sync.Mutex
	f    *os.File
	size int64
}

// OpenLogFile opens (or creates) path for appending. When it grows past max
// bytes it becomes path.1, path.1 becomes path.2, and so on up to keep files.
func OpenLogFile(path string, max int64, keep int) (*LogFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	l := &LogFile{path: path, max: max, keep: keep}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *LogFile) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return errors.Join(err, f.Close())
	}
	l.f, l.size = f, info.Size()
	return nil
}

func (l *LogFile) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return 0, os.ErrClosed
	}
	if l.max > 0 && l.size+int64(len(p)) > l.max {
		l.rotate()
	}
	n, err := l.f.Write(p)
	l.size += int64(n)
	return n, err
}

// rotate shifts the old files along. Failures are not fatal: at worst the
// current file keeps growing, which is better than losing what it says.
func (l *LogFile) rotate() {
	l.f.Close()
	for i := l.keep - 1; i >= 1; i-- {
		os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1))
	}
	if l.keep > 0 {
		os.Rename(l.path, l.path+".1")
	}
	if err := l.open(); err != nil {
		l.f = nil
	}
}

// Close closes the file.
func (l *LogFile) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}
