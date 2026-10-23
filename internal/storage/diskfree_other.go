//go:build !windows && !linux && !darwin

package storage

func diskFree(string) (uint64, bool) { return 0, false }
