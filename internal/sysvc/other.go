//go:build !windows && !linux

package sysvc

import (
	"net"
	"time"
)

// Elsewhere — macOS — there is no service to install: the headless mode runs
// under launchd instead. These keep the callers free of build tags.

func Supported() bool                      { return false }
func IsService() bool                      { return false }
func IsElevated() bool                     { return false }
func AttachConsole()                       {}
func DataDir() (string, error)             { return "", ErrUnsupported }
func StatusDir() (string, error)           { return "", ErrUnsupported }
func CheckLocation(string) error           { return ErrUnsupported }
func Query() (Info, error)                 { return Info{}, nil }
func Install(string, string, string) error { return ErrUnsupported }
func Allow(string) error                   { return ErrUnsupported }
func CurrentUserSID() (string, error)      { return "", ErrUnsupported }
func ListenControl() (net.Listener, error) { return nil, ErrUnsupported }
func DialControl(time.Duration) (net.Conn, error) {
	return nil, ErrUnsupported
}

func Uninstall(bool) error { return ErrUnsupported }
func Start() error         { return ErrUnsupported }
func Stop() error          { return ErrUnsupported }
func Run(string) error     { return ErrUnsupported }
func RunElevated(string, []string, time.Duration) (uint32, error) {
	return 0, ErrUnsupported
}
func ownLikeDir(string) {}
