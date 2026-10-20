package storage

import (
	"errors"
	"os"
	"path/filepath"
)

// ErrDirInUse means another SyslogStudio process already has the data
// directory open.
var ErrDirInUse = errors.New("another SyslogStudio process is already using this data directory")

// lockFileName sits in the data directory for as long as an engine has it
// open. The lock is the operating system's, held by an open handle, so a
// process that dies releases it — the file left behind means nothing.
const lockFileName = "engine.lock"

// LockDir claims a data directory for this process.
//
// One engine per directory is not a convention, it is what keeps the database
// intact: two processes would both run retention, both rebuild the search
// index, and — with encryption on — both re-encrypt the file on exit, the
// second over the first. The desktop application and a headless host started
// on the same directory are exactly that case.
func LockDir(dir string) (release func(), err error) {
	if dir == "" {
		return func() {}, nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	return lockFile(filepath.Join(dir, lockFileName))
}
