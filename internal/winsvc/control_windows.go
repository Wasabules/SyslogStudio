//go:build windows

package winsvc

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
)

// ControlPipe is where windows connect to drive the service. Remote clients
// are refused by the pipe itself: this is for the machine's own users.
const ControlPipe = `\\.\pipe\SyslogStudio`

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

// addOperator allows an account, given by SID, to drive the service. added
// is false when it was allowed already.
func addOperator(dir, sid string) (added bool, err error) {
	s, err := windows.StringToSid(sid)
	if err != nil {
		return false, fmt.Errorf("%q is not an account's SID", sid)
	}
	sid = s.String()
	ops, err := loadOperators(dir)
	if err != nil {
		return false, err
	}
	for _, op := range ops {
		if strings.EqualFold(op.SID, sid) {
			return false, nil
		}
	}
	op := Operator{SID: sid}
	if account, domain, _, err := s.LookupAccount(""); err == nil {
		op.Name = account
		if domain != "" {
			op.Name = domain + `\` + account
		}
	}
	ops = append(ops, op)
	data, err := json.MarshalIndent(ops, "", "  ")
	if err != nil {
		return false, err
	}
	if err := os.WriteFile(filepath.Join(dir, operatorsFile), data, 0600); err != nil {
		return false, fmt.Errorf("write %s: %w", operatorsFile, err)
	}
	return true, nil
}

// controlSDDL is the pipe's security descriptor: the system, administrators
// (elevated: a filtered token holds the group for denying only), the account
// serving it, and the operators, who may read and write — talk to it — and
// nothing more.
//
// The serving account is not a formality. Each connection is accepted on a
// new instance of the pipe, which the server opens like any other caller,
// against this very descriptor: leave its account out and the service creates
// the pipe, then is refused every instance it needs to answer on.
func controlSDDL(self string, ops []Operator) string {
	var b strings.Builder
	b.WriteString("D:P(A;;GA;;;SY)(A;;GA;;;BA)")
	fmt.Fprintf(&b, "(A;;GA;;;%s)", self)
	for _, op := range ops {
		fmt.Fprintf(&b, "(A;;GRGW;;;%s)", op.SID)
	}
	return b.String()
}

// ListenControl opens the service's pipe for its operators. Called by the
// service as it starts; an operator added later is let in by restarting it,
// which Allow does.
func ListenControl() (net.Listener, error) {
	dir, err := DataDir()
	if err != nil {
		return nil, err
	}
	ops, err := loadOperators(dir)
	if err != nil {
		return nil, err
	}
	self, err := CurrentUserSID()
	if err != nil {
		return nil, err
	}
	return listenControl(ControlPipe, self, ops)
}

func listenControl(path, self string, ops []Operator) (net.Listener, error) {
	return winio.ListenPipe(path, &winio.PipeConfig{
		SecurityDescriptor: controlSDDL(self, ops),
		InputBufferSize:    64 << 10,
		OutputBufferSize:   64 << 10,
	})
}

// DialControl connects to the running service, and checks that what answers
// is the service and not a program that took its pipe's name first: a window
// hands the service its settings, credentials included.
func DialControl(timeout time.Duration) (net.Conn, error) {
	info, err := Query()
	if err != nil {
		return nil, err
	}
	if !info.Installed || info.State != "running" || info.PID == 0 {
		return nil, fmt.Errorf("the service is not running")
	}
	return dialControl(ControlPipe, timeout, info.PID)
}

func dialControl(path string, timeout time.Duration, wantPID uint32) (net.Conn, error) {
	conn, err := winio.DialPipe(path, &timeout)
	if err != nil {
		if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
			return nil, ErrAccessDenied
		}
		return nil, err
	}
	if wantPID != 0 {
		fd, ok := conn.(interface{ Fd() uintptr })
		var pid uint32
		if !ok || windows.GetNamedPipeServerProcessId(windows.Handle(fd.Fd()), &pid) != nil || pid != wantPID {
			conn.Close()
			return nil, ErrNotService
		}
	}
	return conn, nil
}

// CurrentUserSID is the SID of the account this process runs as.
func CurrentUserSID() (string, error) {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return "", err
	}
	return u.User.Sid.String(), nil
}

// Allow lets an account drive the service from a window, and restarts the
// service if it runs so its pipe lets that account in. It must run elevated.
func Allow(sid string) error {
	if !IsElevated() {
		return fmt.Errorf("allowing an account needs administrator rights")
	}
	dir, err := DataDir()
	if err != nil {
		return err
	}
	added, err := addOperator(dir, sid)
	if err != nil || !added {
		return err
	}
	m, s, err := open()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	defer s.Close()
	if st, err := s.Query(); err != nil || st.State != svc.Running {
		return nil
	}
	if err := stopAndWait(s); err != nil {
		return err
	}
	statusDir, _ := StatusDir()
	return startAndWait(s, statusDir)
}
