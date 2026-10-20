//go:build windows

package main

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"SyslogStudio/internal/storage"
)

// TestHelperHoldPort is not a test: it is the other program, holding a TCP
// port until its input closes.
func TestHelperHoldPort(t *testing.T) {
	if os.Getenv("SYSLOGSTUDIO_HOLD_PORT") == "" {
		t.Skip("helper process")
	}
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		os.Exit(1)
	}
	fmt.Println(l.Addr().(*net.TCPAddr).Port)
	io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

// holdPort starts another process holding a port, and returns it.
func holdPort(t *testing.T) (port, pid int) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestHelperHoldPort$")
	cmd.Env = append(os.Environ(), "SYSLOGSTUDIO_HOLD_PORT=1")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		stdin.Close()
		cmd.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatalf("the helper did not say its port: %v", err)
	}
	port, err = strconv.Atoi(strings.TrimSpace(line))
	if err != nil {
		t.Fatalf("the helper said %q", line)
	}
	return port, cmd.Process.Pid
}

// What the user met: a port another program holds — VMware's NAT on 514 —
// failed the start with "only one usage of each socket address", which names
// no one. The error now says who holds it.
func TestApp_StartNamesWhoHoldsThePort(t *testing.T) {
	port, pid := holdPort(t)

	a := newAppIn(storage.NewConfigStoreAt(t.TempDir()))
	a.openLocal()
	t.Cleanup(a.stopLink)

	cfg := a.GetDefaultConfig()
	cfg.UDPEnabled, cfg.TCPEnabled, cfg.TLSEnabled = false, true, false
	cfg.BindAddress = "127.0.0.1"
	cfg.TCPPort = port
	err := a.StartServer(cfg)
	if err == nil {
		t.Fatal("started on a port another process holds")
	}
	want := fmt.Sprintf("TCP port %d is held by %s (PID %d)", port, filepath.Base(os.Args[0]), pid)
	if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
		t.Fatalf("error: %v\nwant it to say: %s", err, want)
	}
	if a.GetServerStatus().Running {
		t.Fatal("running with nothing listening")
	}
}
