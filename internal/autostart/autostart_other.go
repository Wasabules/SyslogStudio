//go:build !windows && !darwin && !linux

package autostart

import "errors"

const isCaseInsensitive = false

var errUnsupported = errors.New("starting at sign-in is not supported on this platform")

func read() (string, bool, bool) { return "", false, false }
func write(string) error         { return errUnsupported }
func remove() error              { return nil }
