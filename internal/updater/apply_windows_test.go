package updater

import "testing"

func TestInstalledAt(t *testing.T) {
	const (
		pf      = `C:\Program Files`
		la      = `C:\Users\u\AppData\Local`
		allDir  = `C:\Program Files\SyslogStudio`
		userDir = `C:\Users\u\AppData\Local\SyslogStudio`
	)
	tests := []struct {
		name       string
		dir        string
		registered []string
		want       bool
	}{
		{"per-user copy, registered", userDir, []string{userDir}, true},
		{"all-users copy, registered", allDir, []string{allDir}, true},
		// The per-user entry is found first; the all-users copy running must
		// still update through the installer, not try to replace itself in
		// Program Files without administrator rights.
		{"all-users copy, both registered", allDir, []string{userDir, allDir}, true},
		{"per-user copy, both registered", userDir, []string{userDir, allDir}, true},
		{"portable copy beside an install", `D:\tools\SyslogStudio`, []string{userDir, allDir}, false},
		{"sibling folder is not under", `C:\Program Files\SyslogStudio Portable`, []string{allDir}, false},
		{"nothing registered, Program Files", allDir, nil, true},
		{"nothing registered, local app data", userDir, nil, true},
		{"nothing registered, elsewhere", `D:\tools`, nil, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := installedAt(tt.dir, tt.registered, pf, la); got != tt.want {
				t.Errorf("installedAt(%q, %q) = %v, want %v", tt.dir, tt.registered, got, tt.want)
			}
		})
	}
}
