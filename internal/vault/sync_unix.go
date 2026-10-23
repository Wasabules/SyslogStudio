//go:build !windows

package vault

import "os"

// syncDir makes a rename durable: on Unix the directory entry is data too.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}
