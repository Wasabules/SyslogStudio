//go:build windows

package storage

import (
	"errors"

	"golang.org/x/sys/windows"
)

// lockFile opens the lock file with no sharing at all: while this handle is
// open, any other open of the same file fails with a sharing violation.
func lockFile(path string) (func(), error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	h, err := windows.CreateFile(p,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0, // no sharing: this is the lock
		nil,
		windows.OPEN_ALWAYS,
		windows.FILE_ATTRIBUTE_NORMAL,
		0)
	if err != nil {
		if errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
			return nil, ErrDirInUse
		}
		return nil, err
	}
	return func() { windows.CloseHandle(h) }, nil
}
