//go:build windows

package portowner

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func checkSelf(t *testing.T, proto string, port int) {
	t.Helper()
	o, ok := Find(proto, port)
	if !ok {
		t.Fatalf("%s %d: no owner found", proto, port)
	}
	if o.PID != uint32(os.Getpid()) {
		t.Fatalf("%s %d: owner %v, this test is PID %d", proto, port, o, os.Getpid())
	}
	exe, _ := os.Executable()
	if !strings.EqualFold(o.Name, filepath.Base(exe)) {
		t.Fatalf("%s %d: owner named %q, this test is %q", proto, port, o.Name, filepath.Base(exe))
	}
}

func TestFind_TCP(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	checkSelf(t, "tcp", l.Addr().(*net.TCPAddr).Port)
}

func TestFind_UDP(t *testing.T) {
	c, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	checkSelf(t, "udp", c.LocalAddr().(*net.UDPAddr).Port)
}

// A listener with no address binds [::], dual-stack: that is how the
// receiver listens by default, and it shows in the IPv6 tables only.
func TestFind_DualStack(t *testing.T) {
	c, err := net.ListenPacket("udp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	checkSelf(t, "udp", c.LocalAddr().(*net.UDPAddr).Port)

	l, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	checkSelf(t, "tcp", l.Addr().(*net.TCPAddr).Port)
}

func TestFind_FreePort(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	if o, ok := Find("tcp", port); ok {
		t.Fatalf("a closed port is held by %v", o)
	}
}
