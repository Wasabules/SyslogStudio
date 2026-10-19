//go:build linux

package autostart

import "testing"

// useAgentDir only exists on macOS; Linux tests use XDG_CONFIG_HOME instead.
func useAgentDir(t *testing.T, dir string) string { t.Helper(); return dir }
