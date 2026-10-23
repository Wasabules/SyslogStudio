//go:build linux || darwin

package storage

import "golang.org/x/sys/unix"

// diskFree is the space left to this user on the volume holding dir.
func diskFree(dir string) (uint64, bool) {
	var st unix.Statfs_t
	if unix.Statfs(dir, &st) != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true
}
