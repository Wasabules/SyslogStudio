package simulator

import (
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"SyslogStudio/internal/models"
)

const (
	// dialTimeout bounds the wait for a connection-oriented destination.
	dialTimeout = 5 * time.Second
	// writeTimeout bounds a single send, so one unresponsive collector cannot
	// stall the run for every other destination.
	writeTimeout = 5 * time.Second
	// reconnectInterval is how long a failed TCP/TLS destination waits before
	// trying again. Without it, a refused port produces a dial per message.
	reconnectInterval = 3 * time.Second
	// maxReportedErrorLen keeps a transport error short enough for the status
	// panel; the full text is in the log.
	maxReportedErrorLen = 160
)

// sender delivers messages to one destination. UDP is connectionless and
// effectively cannot fail at send time; TCP and TLS hold a connection and
// reconnect on their own, because the collector under test is routinely
// restarted mid-run — that is often the thing being tested.
type sender struct {
	dest models.SimulatorDestination

	mu       sync.Mutex
	conn     net.Conn
	lastDial time.Time

	sent      atomic.Int64
	failed    atomic.Int64
	connected atomic.Bool

	errMu   sync.Mutex
	lastErr string
}

func newSender(d models.SimulatorDestination) *sender {
	return &sender{dest: d}
}

func (s *sender) addr() string {
	return net.JoinHostPort(s.dest.Host, strconv.Itoa(s.dest.Port))
}

// connect establishes the transport. UDP gets a "connected" socket so writes
// need no address and errors surface locally.
func (s *sender) connect() error {
	switch s.dest.Protocol {
	case "udp":
		c, err := net.DialTimeout("udp", s.addr(), dialTimeout)
		if err != nil {
			return err
		}
		s.conn = c
	case "tcp":
		c, err := net.DialTimeout("tcp", s.addr(), dialTimeout)
		if err != nil {
			return err
		}
		s.conn = c
	case "tls":
		d := &net.Dialer{Timeout: dialTimeout}
		c, err := tls.DialWithDialer(d, "tcp", s.addr(), &tls.Config{
			// The collector on the other end is usually this very app, running
			// a self-signed certificate it generated itself. Verification is
			// therefore opt-out per destination rather than absolute, and the
			// UI says so.
			InsecureSkipVerify: s.dest.InsecureSkipVerify, //nolint:gosec // deliberate, per-destination
			MinVersion:         tls.VersionTLS12,
		})
		if err != nil {
			return err
		}
		s.conn = c
	default:
		return fmt.Errorf("unknown protocol %q", s.dest.Protocol)
	}
	s.connected.Store(true)
	return nil
}

// ensure returns a usable connection, redialling at most once per
// reconnectInterval so a down collector does not turn into a dial storm.
func (s *sender) ensure() (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn, nil
	}
	if time.Since(s.lastDial) < reconnectInterval {
		return nil, fmt.Errorf("waiting to reconnect to %s", s.addr())
	}
	s.lastDial = time.Now()
	if err := s.connect(); err != nil {
		s.connected.Store(false)
		return nil, err
	}
	return s.conn, nil
}

// send delivers one message. TCP and TLS use non-transparent framing (a
// trailing LF), which is what RFC 6587 §3.4.2 describes and what the collector
// falls back to; UDP carries one message per datagram with no delimiter.
func (s *sender) send(wire string) {
	conn, err := s.ensure()
	if err != nil {
		s.fail(err)
		return
	}

	payload := wire
	if s.dest.Protocol != "udp" {
		payload += "\n"
	}

	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if _, err := conn.Write([]byte(payload)); err != nil {
		s.drop()
		s.fail(err)
		return
	}
	s.sent.Add(1)
}

// drop closes the connection so the next send redials. UDP is left alone: a
// write error there is local (an unreachable host returning ICMP), and the
// socket stays perfectly usable.
func (s *sender) drop() {
	if s.dest.Protocol == "udp" {
		return
	}
	s.mu.Lock()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.mu.Unlock()
	s.connected.Store(false)
}

func (s *sender) fail(err error) {
	s.failed.Add(1)
	msg := err.Error()
	if len(msg) > maxReportedErrorLen {
		msg = msg[:maxReportedErrorLen] + "…"
	}
	s.errMu.Lock()
	s.lastErr = msg
	s.errMu.Unlock()
}

func (s *sender) close() {
	s.mu.Lock()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.mu.Unlock()
	s.connected.Store(false)
}

func (s *sender) status() models.SimulatorDestinationStatus {
	s.errMu.Lock()
	lastErr := s.lastErr
	s.errMu.Unlock()
	return models.SimulatorDestinationStatus{
		ID:        s.dest.ID,
		Name:      s.dest.Name,
		Sent:      s.sent.Load(),
		Failed:    s.failed.Load(),
		Connected: s.connected.Load(),
		LastError: lastErr,
	}
}
