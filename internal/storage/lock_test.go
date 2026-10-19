package storage

import (
	"errors"
	"testing"
)

func TestLockDir_OneHolderAtATime(t *testing.T) {
	dir := t.TempDir()
	release, err := LockDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockDir(dir); !errors.Is(err, ErrDirInUse) {
		t.Fatalf("a second claim on the same directory should fail with ErrDirInUse, got %v", err)
	}
	release()

	again, err := LockDir(dir)
	if err != nil {
		t.Fatalf("the directory should be free once released: %v", err)
	}
	again()
}
