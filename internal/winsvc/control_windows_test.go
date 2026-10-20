//go:build windows

package winsvc

import (
	"errors"
	"fmt"
	"io"
	"net"
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
	got := controlSDDL("S-1-5-80-1-2-3-4-5", []Operator{{SID: "S-1-5-21-1-2-3-1001"}})
	want := "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;S-1-5-80-1-2-3-4-5)(A;;GRGW;;;S-1-5-21-1-2-3-1001)"
	if got != want {
		t.Fatalf("SDDL:\n got %s\nwant %s", got, want)
	}
}

// system is an account the test does not run as, standing in for the
// service's when the test is the operator.
const system = "S-1-5-18"

// serveHello answers every connection with one line.
func serveHello(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		c.Write([]byte("hello\n"))
		c.Close()
	}
}

func readHello(t *testing.T, conn net.Conn) {
	t.Helper()
	defer conn.Close()
	buf := make([]byte, 6)
	if _, err := io.ReadFull(conn, buf); err != nil || string(buf) != "hello\n" {
		t.Fatalf("read %q, %v", buf, err)
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

// What the service meets: its own account is not an operator, and every
// connection is answered on a new instance of the pipe, which it opens against
// the pipe's own descriptor. Without its account in there, it created the pipe
// and was then refused every instance — windows timed out on a pipe whose
// every instance was "busy". Run unelevated, this test is that service.
func TestControlPipe_ServesWithItsOwnAccount(t *testing.T) {
	me, err := CurrentUserSID()
	if err != nil {
		t.Fatal(err)
	}
	path := testPipe(t)
	l, err := listenControl(path, me, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go serveHello(l)

	// More than once: each connection needs an instance of its own.
	for i := 0; i < 3; i++ {
		conn, err := dialControl(path, 2*time.Second, uint32(os.Getpid()))
		if err != nil {
			t.Fatalf("connection %d: %v", i+1, err)
		}
		readHello(t, conn)
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
	l, err := listenControl(path, system, []Operator{{SID: me}})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go serveHello(l)

	conn, err := dialControl(path, 2*time.Second, uint32(os.Getpid()))
	if err != nil {
		t.Fatalf("an operator could not connect: %v", err)
	}
	readHello(t, conn)

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
	l, err := listenControl(path, system, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if _, err := dialControl(path, 2*time.Second, 0); !errors.Is(err, ErrAccessDenied) {
		t.Fatalf("a non-operator connecting: %v", err)
	}
}
