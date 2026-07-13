package syslog

import (
	"net"
	"strconv"
	"testing"
	"time"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
)

// TestStop_UnderTraffic floods the UDP listener and calls Stop() while
// datagrams are in flight. The previous code closed workCh in Stop while
// producers were still sending into it -> "send on closed channel" panic.
// With workers exiting via ctx (no close), this must not panic and must run
// clean under -race.
func TestStop_UnderTraffic(t *testing.T) {
	s := NewSyslogServer(event.NewMockEventEmitter(), nil)
	cfg := models.DefaultServerConfig()
	cfg.BindAddress = "127.0.0.1"
	cfg.UDPEnabled = true
	cfg.UDPPort = freeUDPPort(t)
	cfg.TCPEnabled = false
	cfg.TLSEnabled = false
	if err := s.Start(cfg); err != nil {
		t.Fatalf("start: %v", err)
	}

	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.UDPPort))
	stop := make(chan struct{})
	go func() {
		conn, err := net.Dial("udp", addr)
		if err != nil {
			return
		}
		defer conn.Close()
		msg := []byte("<13>1 2003-10-11T22:14:15Z host app - - - flood")
		for {
			select {
			case <-stop:
				return
			default:
				_, _ = conn.Write(msg)
			}
		}
	}()

	time.Sleep(80 * time.Millisecond) // let datagrams flow through the workers

	done := make(chan struct{})
	go func() { s.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Stop did not return under traffic")
	}
	close(stop)
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}
