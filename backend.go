package main

import (
	"SyslogStudio/internal/engine"
	"SyslogStudio/internal/remote"
)

// Backend is what the window drives: the receiver, its storage, its rules and
// its certificates — every engine method the frontend calls. App embeds it, so
// each is a method Wails binds, without a forwarding stub apiece.
//
// It is defined in package remote, because the system service answers it too:
// a window driving the service satisfies the same interface, and the frontend
// cannot tell the difference.
type Backend = remote.Backend

// keyMaterial is what the window needs from the engine and must never hand to
// the frontend. Wails binds every exported method of App, promoted ones
// included, so private keys and credentials stay off the embedded interface:
// the window writes them to the files its user picks, or to the service it
// installs, and no script can read them.
type keyMaterial interface {
	CACertificatePEM() ([]byte, error)
	ServerCertificatePEM() (certPEM, keyPEM []byte, err error)
	ExportBundle() (engine.Bundle, error)
}

// The in-process engine is a complete backend, and so is a window's
// connection to the service.
var (
	_ Backend     = (*engine.Engine)(nil)
	_ keyMaterial = (*engine.Engine)(nil)
	_ keyMaterial = (*remote.Client)(nil)
)
