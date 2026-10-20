// Package winsvc runs SyslogStudio as a Windows service: a headless process
// that Windows starts at boot, before anyone signs in, under an account of its
// own, with its configuration and database in a machine-wide directory only
// administrators can read.
//
// Installing it needs an administrator, once. The desktop application does the
// rest of the work unprivileged — it prepares the configuration to hand over,
// then runs only the steps that need elevation in a separate, elevated copy of
// itself — so the window never runs elevated and the prompt says exactly what
// is being done.
//
// Elsewhere there is no service to install: the same headless mode runs under
// systemd or launchd, which the platform's administrators already know.
package winsvc

import (
	"encoding/json"
	"errors"
	"os"
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

// ErrUnsupported is returned outside Windows.
var ErrUnsupported = errors.New("the system service is only available on Windows; elsewhere, run SyslogStudio --headless under the platform's service manager")

// ErrCancelled means the user declined the administrator prompt.
var ErrCancelled = errors.New("the administrator prompt was declined")

// ErrAccessDenied means this account is not one of the service's operators.
var ErrAccessDenied = errors.New("this account is not allowed to drive the service")

// ErrNotService means something other than the service holds its pipe.
var ErrNotService = errors.New("the program answering on the service's pipe is not the SyslogStudio service")

// Operator is an account allowed to drive the service from a window.
type Operator struct {
	SID  string `json:"sid"`
	Name string `json:"name,omitempty"`
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
	_ = os.WriteFile(path, data, 0600)
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
