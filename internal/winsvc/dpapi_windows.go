//go:build windows

package winsvc

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// MachineSealer protects the service's credentials and private keys with
// DPAPI, at machine scope.
//
// Machine scope, not the service account's own, because the files are written
// by the elevated installer, which runs as the administrator who approved it —
// and a blob sealed for one account cannot be opened by another. Machine scope
// binds them to this computer instead: a copy carried elsewhere is useless.
// Who may read them on this computer is decided by the directory's access
// rules, which admit only the service, SYSTEM and administrators.
type MachineSealer struct{}

// entropy ties the blobs to SyslogStudio, so another program using machine
// scope DPAPI on the same computer cannot open them by accident.
var entropy = []byte("SyslogStudio service credentials v1")

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func take(out *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...)
}

// Seal encrypts p for this computer.
func (MachineSealer) Seal(p []byte) ([]byte, error) {
	var out windows.DataBlob
	err := windows.CryptProtectData(blob(p), nil, blob(entropy), 0, nil,
		windows.CRYPTPROTECT_LOCAL_MACHINE|windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, err
	}
	return take(&out), nil
}

// Unseal decrypts what Seal produced on this computer.
func (MachineSealer) Unseal(p []byte) ([]byte, error) {
	var out windows.DataBlob
	err := windows.CryptUnprotectData(blob(p), nil, blob(entropy), 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, err
	}
	return take(&out), nil
}
