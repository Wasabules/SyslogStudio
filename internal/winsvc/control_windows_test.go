//go:build windows

package winsvc

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testPipe(t *testing.T) string {
	return fmt.Sprintf(`\\.\pipe\SyslogStudio-test-%d-%d`, os.Getpid(), time.Now().UnixNano())
}

func TestControlSDDL(t *testing.T) {
	got := controlSDDL([]Operator{{SID: "S-1-5-21-1-2-3-1001"}})
	want := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-1-2-3-1001)"
	if got != want {
		t.Fatalf("SDDL:\n got %s\nwant %s", got, want)
	}
}

func TestAddOperator(t *testing.T) {
	dir := t.TempDir()
	me, err := CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	if added, err := addOperator(dir, me); err != nil || !added {
		t.Fatalf("first add: %v %v", added, err)
	}
	if added, err := addOperator(dir, strings.ToLower(me)); err != nil || added {
		t.Fatalf("the same account again: %v %v", added, err)
	}
	if _, err := addOperator(dir, "not-a-sid"); err == nil {
		t.Fatal("a malformed SID was accepted")
	}
	ops, err := loadOperators(dir)
	if err != nil || len(ops) != 1 || ops[0].SID != me || ops[0].Name == "" {
		t.Fatalf("operators: %+v %v", ops, err)
	}
	if _, err := os.Stat(filepath.Join(dir, operatorsFile)); err != nil {
		t.Fatal(err)
	}
}

// The pipe lets an operator in, and the window checks that what answers is
// the process it expected.
func TestControlPipe_OperatorConnects(t *testing.T) {
	me, err := CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	path := testPipe(t)
	l, err := listenControl(path, []Operator{{SID: me}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("hello\n"))
			c.Close()
		}
	}()

	conn, err := dialControl(path, 2*time.Second, uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("an operator could not connect: %v", err)
	}
	buf := make([]byte, 6)
	if _, err := conn.Read(buf); err != nil || string(buf) != "hello\n" {
		t.Fatalf("read %q, %v", buf, err)
	}
	conn.Close()

	// The right pipe name held by some other process is refused.
	if _, err := dialControl(path, 2*time.Second, uint32(os.Getpid())+1); !errors.Is(err, ErrNotService) {
		t.Fatalf("another process on the pipe: %v", err)
	}
}

// Someone not on the list is refused by the pipe itself. An elevated test
// run is an administrator, whom the pipe lets in, so it cannot check this.
func TestControlPipe_RefusesOthers(t *testing.T) {
	if IsElevated() {
		t.Skip("running elevated: administrators are allowed")
	}
	path := testPipe(t)
	l, err := listenControl(path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := dialControl(path, 2*time.Second, 0); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("a non-operator connecting: %v", err)
	}
}
