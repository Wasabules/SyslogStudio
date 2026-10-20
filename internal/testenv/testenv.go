// Package testenv keeps tests away from the user's own files.
package testenv

import (
	"fmt"
	"os"
	"testing"
)

// Run runs the tests with the user's directories pointed at a temporary one.
// Code under test that falls back to a default path — the user's database,
// above all — must never reach the real one: a bug that resolved an engine's
// database to it once had a test encrypt a developer's database with the
// test's password. Call it from TestMain:
//
//	func TestMain(m *testing.M) { os.Exit(testenv.Run(m)) }
func Run(m *testing.M) int {
	home, err := os.MkdirTemp("", "syslogstudio-test-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(home)
	for _, v := range []string{"APPDATA", "LOCALAPPDATA", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "HOME", "USERPROFILE"} {
		os.Setenv(v, home)
	}
	return m.Run()
}
