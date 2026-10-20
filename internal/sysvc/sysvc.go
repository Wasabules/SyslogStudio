// Package sysvc runs SyslogStudio as a system service: a headless process the
// system starts at boot, before anyone signs in, under an account of its own,
// with its configuration and database in a machine-wide directory only
// administrators can read. On Windows it is a Windows service; on Linux, a
// systemd unit. The two share everything they can — the configuration bundle,
// the operators, the result of an elevated step — and differ where the
// systems do.
//
// Installing it needs an administrator, once. The desktop application does the
// rest of the work unprivileged — it prepares the configuration to hand over,
// then runs only the steps that need elevation in a separate, elevated copy of
// itself — so the window never runs elevated and the prompt says exactly what
// is being done.
//
// Elsewhere — macOS — there is no service to install: the same headless mode
// runs under launchd, which the platform's administrators already know.
package sysvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"SyslogStudio/internal/engine"
)

const (
	// Name is the service's name in the service manager.
	Name = "SyslogStudio"
	// DisplayName is what services.msc shows.
	DisplayName = "SyslogStudio syslog receiver"
	// Description says what it is to someone who did not install it.
	Description = "Receives, stores and relays syslog messages for SyslogStudio, from boot, with nobody signed in."
	// Account is the virtual account the service runs as: its own identity,
	// with no password to manage and no rights beyond what is granted to it.
	Account = `NT SERVICE\` + Name
	// FirewallRule names the inbound rule the installer adds. A service has no
	// desktop to show Windows' "allow this program" prompt on, so without a
	// rule its listeners would receive nothing at all.
	FirewallRule = "SyslogStudio (service)"
)

// ErrUnsupported is returned where there is no service to install.
var ErrUnsupported = errors.New("the system service is available on Windows and on Linux with systemd; elsewhere, run SyslogStudio --headless under the platform's service manager")

// ErrCancelled means the user declined the administrator prompt.
var ErrCancelled = errors.New("the administrator prompt was declined")

// ErrAccessDenied means this account is not one of the service's operators.
var ErrAccessDenied = errors.New("this account is not allowed to drive the service")

// ErrNotService means something other than the service holds its channel.
var ErrNotService = errors.New("the program answering on the service's channel is not the SyslogStudio service")

// Operator is an account allowed to drive the service from a window.
type Operator struct {
	// SID identifies the account: its SID on Windows, its uid on Linux.
	SID  string `json:"sid"`
	Name string `json:"name,omitempty"`
}

// operatorsFile lists the accounts allowed to drive the service from a
// window, in the service's own directory.
const operatorsFile = "operators.json"

// Operators lists the accounts allowed to drive the service.
func Operators() ([]Operator, error) {
	dir, err := DataDir()
	if err != nil {
		return nil, err
	}
	return loadOperators(dir)
}

func loadOperators(dir string) ([]Operator, error) {
	data, err := os.ReadFile(filepath.Join(dir, operatorsFile))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var ops []Operator
	if err := json.Unmarshal(data, &ops); err != nil {
		return nil, fmt.Errorf("read %s: %w", operatorsFile, err)
	}
	return ops, nil
}

func saveOperators(dir string, ops []Operator) error {
	data, err := json.MarshalIndent(ops, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, operatorsFile), data, 0600); err != nil {
		return fmt.Errorf("write %s: %w", operatorsFile, err)
	}
	return nil
}

// readBundle reads the configuration the window prepared, and deletes the
// file at once: it holds credentials in the clear.
func readBundle(path string) (engine.Bundle, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return engine.Bundle{}, fmt.Errorf("read the configuration to install: %w", err)
	}
	_ = os.Remove(path)
	var b engine.Bundle
	if err := json.Unmarshal(data, &b); err != nil {
		return engine.Bundle{}, fmt.Errorf("read the configuration to install: %w", err)
	}
	return b, nil
}

// Info is the service manager's view of the service.
type Info struct {
	Installed bool
	// State is stopped, starting, running, stopping, or unknown.
	State      string
	Executable string
	Account    string
	// PID is the service's process while it runs.
	PID uint32
}

// Result is what an elevated command reports back to the window that started
// it. The elevated copy has no console and no window, so a file is the only
// way to say more than an exit code.
type Result struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

// WriteResult records the outcome of an elevated command. A failure to write
// it is not reported: the exit code still says whether it worked.
func WriteResult(path string, err error) {
	if path == "" {
		return
	}
	r := Result{OK: err == nil}
	if err != nil {
		r.Error = err.Error()
	}
	data, _ := json.Marshal(r)
	if os.WriteFile(path, data, 0600) == nil {
		ownLikeDir(path)
	}
}

// ReadResult reads what an elevated command recorded.
func ReadResult(path string) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	var r Result
	if err := json.Unmarshal(data, &r); err != nil {
		return Result{}, err
	}
	return r, nil
}
