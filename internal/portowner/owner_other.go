//go:build !windows

package portowner

// Find is only implemented on Windows; elsewhere the owner is unknown.
func Find(proto string, port int) (Owner, bool) {
	return Owner{}, false
}
