//go:build windows

package autostart

import (
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/windows/registry"
)

// The tests write to a scratch key of their own under HKCU and delete it, so
// the real Run key is never touched.
func scratchRunKey(t *testing.T) {
	t.Helper()
	key := fmt.Sprintf(`Software\SyslogStudio-autostart-test-%d`, time.Now().UnixNano())
	old := runKey
	runKey = key
	t.Cleanup(func() {
		runKey = old
		registry.DeleteKey(registry.CURRENT_USER, key)
	})
}

func TestAutostart_RegistersThisExecutableHidden(t *testing.T) {
	scratchRunKey(t)
	exe := `C:\Program Files\SyslogStudio\SyslogStudio.exe`

	if Get(exe).Enabled {
		t.Fatal("registered before Enable")
	}
	if err := Enable(exe); err != nil {
		t.Fatal(err)
	}
	st := Get(exe)
	if !st.Enabled || !st.MatchesThis || st.Executable != exe {
		t.Fatalf("after Enable: %+v", st)
	}

	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	cmd, _, _ := k.GetStringValue(valueName)
	k.Close()
	if want := `"` + exe + `" ` + BackgroundFlag; cmd != want {
		t.Errorf("Run command = %q, want %q — quoted, and starting hidden", cmd, want)
	}

	// Case does not make it another program on Windows.
	if !Get(`c:\program files\syslogstudio\syslogstudio.exe`).MatchesThis {
		t.Error("the same path in another case was treated as another program")
	}
	if Get(`D:\Portable\SyslogStudio.exe`).MatchesThis {
		t.Error("another copy was taken for this one")
	}

	if err := Disable(); err != nil {
		t.Fatal(err)
	}
	if Get(exe).Enabled {
		t.Fatal("still registered after Disable")
	}
	if err := Disable(); err != nil {
		t.Fatalf("disabling twice: %v", err)
	}
}

func TestCommandExecutable(t *testing.T) {
	for cmd, want := range map[string]string{
		`"C:\Program Files\SyslogStudio\SyslogStudio.exe" --background`: `C:\Program Files\SyslogStudio\SyslogStudio.exe`,
		`C:\Tools\SyslogStudio.exe --background`:                        `C:\Tools\SyslogStudio.exe`,
		`C:\Tools\SyslogStudio.exe`:                                     `C:\Tools\SyslogStudio.exe`,
	} {
		if got := commandExecutable(cmd); got != want {
			t.Errorf("commandExecutable(%q) = %q, want %q", cmd, got, want)
		}
	}
}
