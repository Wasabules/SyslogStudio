package main

import (
	"bytes"
	"os"
	"testing"
)

// makensis reads a script without a byte order mark in the system's ANSI code
// page, which garbled every accented string of the French installer
// ("PortÃ©e"). Editors drop a BOM without a word, and nothing else would
// notice before someone ran the installer.
func TestInstallerScriptKeepsItsUTF8BOM(t *testing.T) {
	data, err := os.ReadFile("build/windows/installer/project.nsi")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}) {
		t.Fatal("build/windows/installer/project.nsi lost its UTF-8 byte order mark: makensis would read it as ANSI and garble the accented strings")
	}
}
