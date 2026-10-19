//go:build darwin

package autostart

import (
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// The file system macOS ships is case-insensitive by default.
const isCaseInsensitive = true

const agentLabel = "com.wasabules.syslogstudio"

// agentDir is overridable so tests do not touch the real LaunchAgents.
var agentDir = func() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "LaunchAgents"), nil
}

func agentPath() (string, error) {
	dir, err := agentDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, agentLabel+".plist"), nil
}

func read() (string, bool, bool) {
	path, err := agentPath()
	if err != nil {
		return "", false, false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", false, true
	}
	return plistProgram(data), true, true
}

func write(exe string) error {
	path, err := agentPath()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>` + agentLabel + `</string>
	<key>ProgramArguments</key>
	<array>
		<string>`)
	xml.EscapeText(&b, []byte(exe))
	b.WriteString(`</string>
		<string>` + BackgroundFlag + `</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>ProcessType</key>
	<string>Interactive</string>
</dict>
</plist>
`)
	return os.WriteFile(path, []byte(b.String()), 0644)
}

func remove() error {
	path, err := agentPath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// plistProgram reads the first ProgramArguments string back.
func plistProgram(data []byte) string {
	s := string(data)
	i := strings.Index(s, "<key>ProgramArguments</key>")
	if i < 0 {
		return ""
	}
	s = s[i:]
	start := strings.Index(s, "<string>")
	end := strings.Index(s, "</string>")
	if start < 0 || end < start {
		return ""
	}
	var out strings.Builder
	d := xml.NewDecoder(strings.NewReader("<x>" + s[start+len("<string>"):end] + "</x>"))
	for {
		tok, err := d.Token()
		if err != nil {
			break
		}
		if cd, ok := tok.(xml.CharData); ok {
			out.Write(cd)
		}
	}
	return out.String()
}
