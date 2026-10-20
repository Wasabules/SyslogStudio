//go:build windows

package winsvc

import (
	"bytes"
	"errors"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestMachineSealer_RoundTrip(t *testing.T) {
	plain := []byte(`{"sink-1":{"value":"bearer-token-value"}}`)
	sealed, err := MachineSealer{}.Seal(plain)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte("bearer-token-value")) {
		t.Fatal("sealed output contains the secret")
	}
	got, err := MachineSealer{}.Unseal(sealed)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip: %q", got)
	}

	// Tampering is detected, not decoded into garbage.
	sealed[len(sealed)/2] ^= 0xff
	if _, err := (MachineSealer{}).Unseal(sealed); err == nil {
		t.Error("a tampered blob was accepted")
	}
}

func TestCheckLocation(t *testing.T) {
	pf, err := windows.KnownFolderPath(windows.FOLDERID_ProgramFiles, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckLocation(filepath.Join(pf, "SyslogStudio", "SyslogStudio.exe")); err != nil {
		t.Errorf("a per-machine install was refused: %v", err)
	}

	local, _ := windows.KnownFolderPath(windows.FOLDERID_LocalAppData, 0)
	for _, exe := range []string{
		filepath.Join(local, "SyslogStudio", "SyslogStudio.exe"), // per-user install
		`C:\Users\someone\Downloads\SyslogStudio.exe`,            // portable copy
		pf + `Evil\SyslogStudio.exe`,                             // a sibling that merely starts the same
		pf,                                                       // the folder itself
	} {
		if err := CheckLocation(exe); !errors.Is(err, ErrLocation) {
			t.Errorf("CheckLocation(%q) = %v, want ErrLocation", exe, err)
		}
	}
}

func TestBinaryOf(t *testing.T) {
	for cmd, want := range map[string]string{
		`"C:\Program Files\SyslogStudio\SyslogStudio.exe" service run`: `C:\Program Files\SyslogStudio\SyslogStudio.exe`,
		`C:\Tools\SyslogStudio.exe service run`:                        `C:\Tools\SyslogStudio.exe`,
	} {
		if got := binaryOf(cmd); got != want {
			t.Errorf("binaryOf(%q) = %q, want %q", cmd, got, want)
		}
	}
}

func TestResultRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "result.json")
	WriteResult(path, errors.New("the service stopped while starting: port 514 in use"))
	r, err := ReadResult(path)
	if err != nil || r.OK || r.Error == "" {
		t.Fatalf("failure not recorded: %+v %v", r, err)
	}
	WriteResult(path, nil)
	if r, _ := ReadResult(path); !r.OK {
		t.Fatal("success not recorded")
	}
}

// Query must work for an ordinary user — it is what the settings page calls.
func TestQuery_WorksUnelevated(t *testing.T) {
	if _, err := Query(); err != nil {
		t.Fatalf("querying the service manager: %v", err)
	}
}
