package syslog

import (
	"net"
	"strconv"
	"sync"
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

func tcpBaseConfig(t *testing.T) models.ServerConfig {
	cfg := models.DefaultServerConfig()
	cfg.BindAddress = "127.0.0.1"
	cfg.UDPEnabled = false
	cfg.TLSEnabled = false
	cfg.TCPEnabled = true
	cfg.TCPPort = freeTCPPort(t)
	return cfg
}

// perIPCount reads the live per-source-IP connection count (same package, so it
// may touch unexported state under the same lock the server uses).
func perIPCount(s *SyslogServer, ip string) int {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	return s.connPerIP[ip]
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("condition not met in time: %s", what)
}

// TestStartStopOverlap_NoClobber hammers Start and Stop concurrently. Start
// allocates the conn maps under s.mu while Stop nils them under connsMu; before
// the lifecycle was serialized, an overlapping pair could let a stale Stop null
// the new run's maps, leaving trackConn rejecting every connection. This must
// run clean under -race and leave the server accepting connections afterwards.
func TestStartStopOverlap_NoClobber(t *testing.T) {
	s := NewSyslogServer(event.NewMockEventEmitter(), nil)
	for i := 0; i < 20; i++ {
		cfg := tcpBaseConfig(t)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); _ = s.Start(cfg) }()
		go func() { defer wg.Done(); _ = s.Stop() }()
		wg.Wait()
		_ = s.Stop() // guarantee stopped between iterations
	}

	cfg := tcpBaseConfig(t)
	if err := s.Start(cfg); err != nil {
		t.Fatalf("final start: %v", err)
	}
	defer s.Stop()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.TCPPort))
	var conn net.Conn
	var err error
	for i := 0; i < 50; i++ { // listener may not be ready the instant Start returns
		if conn, err = net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("server not accepting after Start/Stop churn: %v", err)
	}
	conn.Close()
}

// TestPerIPConnLimit_Balance opens connections up to the per-IP cap and verifies
// the counter both counts up and drains back to zero on close, so a busy source
// is never permanently locked out by a leaked count.
func TestPerIPConnLimit_Balance(t *testing.T) {
	s := NewSyslogServer(event.NewMockEventEmitter(), nil)
	cfg := tcpBaseConfig(t)
	cfg.MaxConnsPerIP = 4
	if err := s.Start(cfg); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer s.Stop()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(cfg.TCPPort))

	var conns []net.Conn
	for i := 0; i < cfg.MaxConnsPerIP; i++ {
		c, err := net.DialTimeout("tcp", addr, time.Second)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		conns = append(conns, c)
	}
	waitFor(t, "per-IP count reaches cap", func() bool {
		return perIPCount(s, "127.0.0.1") == cfg.MaxConnsPerIP
	})

	for _, c := range conns {
		c.Close()
	}
	waitFor(t, "per-IP count drains to zero", func() bool {
		return perIPCount(s, "127.0.0.1") == 0
	})
}
