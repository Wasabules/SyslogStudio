//go:build linux || darwin

package autostart

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func scratchDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS == "linux" {
		t.Setenv("XDG_CONFIG_HOME", dir)
		return filepath.Join(dir, "autostart")
	}
	return useAgentDir(t, dir)
}

func TestAutostart_RegistersThisExecutableHidden(t *testing.T) {
	dir := scratchDir(t)
	exe := "/opt/Syslog Studio/SyslogStudio"

	if err := Enable(exe); err != nil {
		t.Fatal(err)
	}
	st := Get(exe)
	if !st.Enabled || !st.MatchesThis || st.Executable != exe {
		t.Fatalf("after Enable: %+v", st)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected one registration file in %s, found %d", dir, len(entries))
	}
	data, _ := os.ReadFile(filepath.Join(dir, entries[0].Name()))
	if !strings.Contains(string(data), BackgroundFlag) {
		t.Error("the registration does not start the application hidden")
	}
	if Get("/usr/bin/SyslogStudio").MatchesThis {
		t.Error("another copy was taken for this one")
	}

	if err := Disable(); err != nil {
		t.Fatal(err)
	}
	if Get(exe).Enabled {
		t.Fatal("still registered after Disable")
	}
}
