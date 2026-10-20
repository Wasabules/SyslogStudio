//go:build windows

package autostart

import (
	"errors"
	"strings"

	"golang.org/x/sys/windows/registry"
)

const isCaseInsensitive = true

// runKey is the per-user Run key, and valueName our entry in it. A variable
// so tests can point it at a scratch key.
var (
	runKey    = `Software\Microsoft\Windows\CurrentVersion\Run`
	valueName = "SyslogStudio"
)

func read() (exe string, ok bool, supported bool) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.QUERY_VALUE)
	if err != nil {
		return "", false, true
	}
	defer k.Close()
	cmd, _, err := k.GetStringValue(valueName)
	if err != nil {
		return "", false, true
	}
	return commandExecutable(cmd), true, true
}

func write(exe string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue(valueName, `"`+exe+`" `+BackgroundFlag)
}

func remove() error {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return nil
		}
		return err
	}
	defer k.Close()
	if err := k.DeleteValue(valueName); err != nil && !errors.Is(err, registry.ErrNotExist) {
		return err
	}
	return nil
}

// commandExecutable takes the program out of a Run command line: quoted, or
// up to the first space.
func commandExecutable(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, `"`) {
		if end := strings.Index(cmd[1:], `"`); end >= 0 {
			return cmd[1 : 1+end]
		}
		return strings.Trim(cmd, `"`)
	}
	if i := strings.IndexByte(cmd, ' '); i >= 0 {
		return cmd[:i]
	}
	return cmd
}
