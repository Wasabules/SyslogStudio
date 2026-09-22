package notify

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// SyslogSinkConfig forwards messages to another collector.
type SyslogSinkConfig struct {
	Address  string `json:"address"`  // host:port
	Protocol string `json:"protocol"` // udp, tcp, tls
	Facility int    `json:"facility"` // 0-23; 16 (local0) is the usual choice
	Hostname string `json:"hostname"` // ours; empty asks the OS
	AppName  string `json:"appName"`  // defaults to SyslogStudio
	Timeout  int    `json:"timeout"`  // seconds; 0 means 5

	// PreserveOrigin sends the original message's hostname and app name rather
	// than ours. That is what makes this a relay instead of a new source: the
	// far collector keeps attributing each line to the device that emitted it.
	PreserveOrigin bool `json:"preserveOrigin,omitempty"`

	// PreserveFacility forwards the original facility instead of the one
	// configured above, for the same reason.
	PreserveFacility bool `json:"preserveFacility,omitempty"`

	// --- TLS, used when Protocol is "tls" ---

	// CAFile verifies the far collector. Empty means the system pool.
	CAFile string `json:"caFile,omitempty"`
	// ClientCertFile and ClientKeyFile enable mutual TLS.
	ClientCertFile string `json:"clientCertFile,omitempty"`
	ClientKeyFile  string `json:"clientKeyFile,omitempty"`
	// InsecureSkipVerify accepts any certificate. Opt-in and surfaced in the
	// UI, because the far end is often another self-signed SyslogStudio.
	InsecureSkipVerify bool `json:"insecureSkipVerify,omitempty"`
}

const (
	defaultSyslogTimeout = 5 * time.Second
	// reconnectInterval throttles redialling a collector that is down, so an
	// unreachable destination does not turn into one dial per message.
	reconnectInterval = 3 * time.Second
)

type syslogSink struct {
	cfg      SyslogSinkConfig
	hostname string
	appName  string
	timeout  time.Duration
	tlsCfg   *tls.Config

	mu       sync.Mutex
	conn     net.Conn
	lastDial time.Time
}

func newSyslogSink(cfg SinkConfig, _ string) (Sink, error) {
	c := cfg.Syslog
	if err := validateSyslogSink(c); err != nil {
		return nil, err
	}

	host := c.Hostname
	if host == "" {
		if h, err := os.Hostname(); err == nil {
			host = h
		} else {
			host = "-"
		}
	}
	app := c.AppName
	if app == "" {
		app = "SyslogStudio"
	}
	timeout := time.Duration(c.Timeout) * time.Second
	if timeout <= 0 {
		timeout = defaultSyslogTimeout
	}

	s := &syslogSink{cfg: c, hostname: host, appName: app, timeout: timeout}

	if c.Protocol == "tls" {
		tlsCfg, err := buildClientTLS(c)
		if err != nil {
			return nil, err
		}
		s.tlsCfg = tlsCfg
	}
	return s, nil
}

func buildClientTLS(c SyslogSinkConfig) (*tls.Config, error) {
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: c.InsecureSkipVerify, //nolint:gosec // opt-in, per sink, shown in the UI
	}
	if c.CAFile != "" {
		pem, err := os.ReadFile(c.CAFile)
		if err != nil {
			return nil, errf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errf("CA file %q contains no usable certificate", c.CAFile)
		}
		cfg.RootCAs = pool
	}
	// Both halves or neither: a cert without its key is a configuration that
	// silently falls back to anonymous, which is not what was asked for.
	if (c.ClientCertFile == "") != (c.ClientKeyFile == "") {
		return nil, errf("mutual TLS needs both a client certificate and a key")
	}
	if c.ClientCertFile != "" {
		pair, err := tls.LoadX509KeyPair(c.ClientCertFile, c.ClientKeyFile)
		if err != nil {
			return nil, errf("load client certificate: %w", err)
		}
		cfg.Certificates = []tls.Certificate{pair}
	}
	if host, _, err := net.SplitHostPort(c.Address); err == nil {
		cfg.ServerName = host
	}
	return cfg, nil
}

func (s *syslogSink) Describe() string {
	return fmt.Sprintf("syslog %s://%s", s.cfg.Protocol, s.cfg.Address)
}

func (s *syslogSink) ensure() (net.Conn, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn, nil
	}
	if time.Since(s.lastDial) < reconnectInterval {
		return nil, errf("waiting to reconnect to %s", s.cfg.Address)
	}
	s.lastDial = time.Now()

	var (
		conn net.Conn
		err  error
	)
	switch s.cfg.Protocol {
	case "udp":
		conn, err = net.DialTimeout("udp", s.cfg.Address, s.timeout)
	case "tcp":
		conn, err = net.DialTimeout("tcp", s.cfg.Address, s.timeout)
	case "tls":
		conn, err = tls.DialWithDialer(&net.Dialer{Timeout: s.timeout}, "tcp", s.cfg.Address, s.tlsCfg)
	default:
		return nil, errf("unknown protocol %q", s.cfg.Protocol)
	}
	if err != nil {
		return nil, err
	}
	s.conn = conn
	return conn, nil
}

func (s *syslogSink) drop() {
	// UDP is left alone: a write error there is local (an ICMP unreachable),
	// and the socket stays perfectly usable.
	if s.cfg.Protocol == "udp" {
		return
	}
	s.mu.Lock()
	if s.conn != nil {
		s.conn.Close()
		s.conn = nil
	}
	s.mu.Unlock()
}

func (s *syslogSink) Send(r Rendered) error {
	conn, err := s.ensure()
	if err != nil {
		return err
	}

	wire := s.frame(r)
	// TCP and TLS use non-transparent framing (a trailing LF), RFC 6587 §3.4.2;
	// UDP carries one message per datagram with no delimiter.
	if s.cfg.Protocol != "udp" {
		wire += "\n"
	}

	_ = conn.SetWriteDeadline(time.Now().Add(s.timeout))
	if _, err := conn.Write([]byte(wire)); err != nil {
		s.drop()
		return err
	}
	return nil
}

// frame builds an RFC 5424 line.
//
// The rendered body becomes the MSG. Severity always comes from the original
// message — a relay that flattened every forwarded line to one severity would
// destroy the far collector's filtering, which is the main thing it is for.
func (s *syslogSink) frame(r Rendered) string {
	facility := s.cfg.Facility
	if s.cfg.PreserveFacility {
		facility = int(r.Msg.Facility)
	}
	pri := facility*8 + int(r.Msg.Severity)

	host, app := s.hostname, s.appName
	if s.cfg.PreserveOrigin {
		if r.Msg.Hostname != "" {
			host = r.Msg.Hostname
		}
		if r.Msg.AppName != "" {
			app = r.Msg.AppName
		}
	}

	ts := r.Msg.Timestamp
	if ts.IsZero() {
		ts = time.Now()
	}

	procID := nilIfEmpty(r.Msg.ProcID)
	msgID := nilIfEmpty(r.Msg.MsgID)

	return fmt.Sprintf("<%d>1 %s %s %s %s %s - %s",
		pri,
		ts.Format("2006-01-02T15:04:05.000Z07:00"),
		sanitizeField(host),
		sanitizeField(app),
		sanitizeField(procID),
		sanitizeField(msgID),
		sanitizeMSG(r.Body),
	)
}

func nilIfEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "-"
	}
	return s
}

// sanitizeField keeps a header field to one printable token.
//
// A space in HOSTNAME or APP-NAME shifts every later field by one, so a
// hostile device could inject its own PROCID, MSGID and structured data into
// the line the far collector parses. RFC 5424 forbids spaces here; nothing
// forbids a device from sending them.
func sanitizeField(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 33 || r > 126 {
			return -1
		}
		return r
	}, s)
	if s == "" {
		return "-"
	}
	// RFC 5424 caps these fields; a longer value is a malformed line to the
	// receiver, and an unbounded one is a way to push a relay's buffers.
	if len(s) > 255 {
		s = s[:255]
	}
	return s
}

// sanitizeMSG strips the framing characters from the message body.
//
// A newline inside MSG ends the record under LF framing, so everything after it
// arrives as a SEPARATE syslog line — with whatever PRI and content the sender
// chose. That is log injection: a device that can send "\n<0>1 ..." forges an
// emergency from any host it likes on the far collector.
func sanitizeMSG(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', 0:
			return ' '
		}
		return r
	}, s)
}

func (s *syslogSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		err := s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}
