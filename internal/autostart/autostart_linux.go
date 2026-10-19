//go:build linux

package autostart

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

const isCaseInsensitive = false

const desktopName = "syslogstudio.desktop"

// autostartDir follows the XDG base directory rules. Overridable for tests.
var autostartDir = func() (string, error) {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "autostart"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "autostart"), nil
}

func entryPath() (string, error) {
	dir, err := autostartDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, desktopName), nil
}

func read() (string, bool, bool) {
	path, err := entryPath()
	if err != nil {
		return "", false, false
	}
	f, err := os.Open(path)
	if err != nil {
		return "", false, true
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if rest, ok := strings.CutPrefix(sc.Text(), "Exec="); ok {
			return execProgram(rest), true, true
		}
	}
	return "", true, true
}

func write(exe string) error {
	path, err := entryPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	entry := "[Desktop Entry]\n" +
		"Type=Application\n" +
		"Name=SyslogStudio\n" +
		"Comment=Syslog receiver, started in the background at sign-in\n" +
		"Exec=" + quoteExec(exe) + " " + BackgroundFlag + "\n" +
		"Terminal=false\n" +
		"X-GNOME-Autostart-enabled=true\n"
	return os.WriteFile(path, []byte(entry), 0644)
}

func remove() error {
	path, err := entryPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// quoteExec quotes a program path the way the desktop entry specification
// asks: double quotes, with backslash, quote, backtick and dollar escaped.
func quoteExec(p string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, "`", "\\`", `$`, `\$`)
	return `"` + r.Replace(p) + `"`
}

func execProgram(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if !strings.HasPrefix(cmd, `"`) {
		if i := strings.IndexByte(cmd, ' '); i >= 0 {
			return cmd[:i]
		}
		return cmd
	}
	var out strings.Builder
	for i := 1; i < len(cmd); i++ {
		c := cmd[i]
		if c == '\\' && i+1 < len(cmd) {
			i++
			out.WriteByte(cmd[i])
			continue
		}
		if c == '"' {
			break
		}
		out.WriteByte(c)
	}
	return out.String()
}
