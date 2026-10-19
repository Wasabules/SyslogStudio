//go:build windows

package winsvc

import (
	"os"

	"golang.org/x/sys/windows"
)

var procAttachConsole = windows.NewLazySystemDLL("kernel32.dll").NewProc("AttachConsole")

// attachParentProcess is ATTACH_PARENT_PROCESS, (DWORD)-1.
const attachParentProcess = ^uintptr(0)

// AttachConsole gives a command typed in a terminal somewhere to print.
//
// SyslogStudio is built as a GUI program, so Windows gives it no console:
// `SyslogStudio.exe service status` would print into the void. When output is
// redirected — to a file, or through a pipe — the handles are real and are
// left alone; otherwise the program attaches to the console of the terminal
// that started it. The terminal does not wait for a GUI program, so the
// output lands after the prompt has returned; piping through `more` avoids
// that.
func AttachConsole() {
	if redirected(windows.STD_OUTPUT_HANDLE) {
		return
	}
	if r, _, _ := procAttachConsole.Call(attachParentProcess); r == 0 {
		return
	}
	if out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = out
		os.Stderr = out
	}
}

func redirected(std uint32) bool {
	h, err := windows.GetStdHandle(std)
	if err != nil || h == 0 || h == windows.InvalidHandle {
		return false
	}
	t, err := windows.GetFileType(h)
	return err == nil && (t == windows.FILE_TYPE_DISK || t == windows.FILE_TYPE_PIPE)
}
