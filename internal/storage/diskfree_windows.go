package storage

import "golang.org/x/sys/windows"

// diskFree is the space left to this user on the volume holding dir.
func diskFree(dir string) (uint64, bool) {
	p, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, false
	}
	var free, total, all uint64
	if windows.GetDiskFreeSpaceEx(p, &free, &total, &all) != nil {
		return 0, false
	}
	return free, true
}
