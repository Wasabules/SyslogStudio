//go:build linux

package sysvc

import (
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseShow(t *testing.T) {
	out := []byte(`LoadState=loaded
ActiveState=active
MainPID=4242
ExecStart={ path=/usr/bin/SyslogStudio ; argv[]=/usr/bin/SyslogStudio service run ; ignore_errors=no ; start_time=[n/a] ; stop_time=[n/a] ; pid=0 ; code=(null) ; status=0/0 }
User=syslogstudio
`)
	info := parseShow(out)
	if !info.Installed || info.State != "running" || info.PID != 4242 ||
		info.Executable != "/usr/bin/SyslogStudio" || info.Account != "syslogstudio" {
		t.Fatalf("parsed: %+v", info)
	}
	if info := parseShow([]byte("LoadState=not-found\nActiveState=inactive\nMainPID=0\n")); info.Installed {
		t.Fatalf("a unit that is not there: %+v", info)
	}
	if info := parseShow([]byte("LoadState=loaded\nActiveState=failed\nMainPID=0\n")); info.State != "stopped" {
		t.Fatalf("a failed unit: %+v", info)
	}
}

func TestUnitFile(t *testing.T) {
	u := unitFile("/opt/Syslog Studio/SyslogStudio")
	for _, want := range []string{
		`ExecStart="/opt/Syslog Studio/SyslogStudio" service run`,
		"User=syslogstudio",
		"AmbientCapabilities=CAP_NET_BIND_SERVICE",
		"CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
		"StateDirectory=syslogstudio",
		"RuntimeDirectory=syslogstudio",
		"WantedBy=multi-user.target",
	} {
		if !strings.Contains(u, want) {
			t.Errorf("the unit lacks %q", want)
		}
	}
	if !strings.Contains(unitFile("/usr/bin/SyslogStudio"), "ExecStart=/usr/bin/SyslogStudio service run") {
		t.Error("a plain path should not be quoted")
	}
}

// A copy in a directory its user owns could be swapped for anything, which
// the service would then run under its account.
func TestCheckLocation_RefusesAUserWritableCopy(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the temporary directory")
	}
	exe := filepath.Join(t.TempDir(), "SyslogStudio")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := CheckLocation(exe); err == nil {
		t.Fatal("a copy its user can replace was accepted")
	}
	if err := CheckLocation("/usr/bin/env"); err != nil {
		t.Fatalf("a packaged program was refused: %v", err)
	}
}

func serveHello(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("{\"hello\":{\"protocol\":1}}\n"))
		c.Close()
	}
}

// The socket lets in root, the service's account and the operators, and
// tells anyone else so — the window shows "Allow my account" for that.
func TestControlSocket_OperatorsOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, controlSocket)
	l, err := listenControl(path, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	// Stand in for a service running as another account than this test.
	l.(*operatorListener).self = -1
	go serveHello(l)

	me := os.Getuid()
	if me == 0 {
		t.Skip("root is always let in")
	}
	if _, err := dialControl(path, 2*time.Second, 0); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("an account that is not an operator: %v", err)
	}

	if _, err := addOperator(dir, strconv.Itoa(me)); err != nil {
		t.Fatal(err)
	}
	c, err := dialControl(path, 2*time.Second, uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("an operator, read afresh without a restart: %v", err)
	}
	got, _ := io.ReadAll(c)
	c.Close()
	if !strings.HasPrefix(string(got), "{\"hello\"") {
		t.Fatalf("the window got %q instead of the hello", got)
	}

	if _, err := dialControl(path, 2*time.Second, uint32(os.Getpid())+1); !errors.Is(err, ErrNotService) {
		t.Fatalf("another process on the socket: %v", err)
	}
}

func TestAddOperator_Linux(t *testing.T) {
	dir := t.TempDir()
	me := strconv.Itoa(os.Getuid())
	if added, err := addOperator(dir, me); err != nil || !added {
		t.Fatalf("first add: %v %v", added, err)
	}
	if added, err := addOperator(dir, me); err != nil || added {
		t.Fatalf("again: %v %v", added, err)
	}
	if _, err := addOperator(dir, "geoffrey"); err == nil {
		t.Fatal("a name was accepted where a uid is needed")
	}
	ops, _ := loadOperators(dir)
	if len(ops) != 1 || ops[0].SID != me || ops[0].Name == "" {
		t.Fatalf("operators: %+v", ops)
	}
}
