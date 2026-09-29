package importer

import (
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

// What automatic detection is expected to make of the formats people actually
// have on disk.
//
// One line per format, taken from what the tool that writes it really emits.
// The table is the specification: a format that is not in it is a format
// nobody has checked, and a format in it that changes behaviour fails here
// before it reaches anyone's screen.
//
// The negative half matters as much. A wide recogniser earns its width only if
// it stays silent on a line it does not understand — an invented hostname or a
// severity read out of an ordinary sentence is worse than an unparsed line,
// because the text still shows while the field quietly lies.

type shapeCase struct {
	name string
	line string
	// The moment, formatted with `layout` (the date alone when the format
	// carries no year of its own and the panel supplies it).
	when   string
	layout string
	sev    string
	host   string
	app    string
	pid    string
	msg    string
	// local marks a line whose timestamp carries no zone AND goes through the
	// wire parser, which reads it in the machine's zone — the same instant the
	// receiver would record for that line (#24). The format panel's timezone
	// governs everything this package parses itself.
	local bool
}

const defaultLayout = "2006-01-02 15:04:05"

func TestAuto_Corpus(t *testing.T) {
	cases := []shapeCase{
		// --- the syslog family ---------------------------------------------
		{
			name: "RFC 5424 with a priority",
			line: `<134>1 2026-03-17T21:42:10Z web-1 sshd 4242 - - Accepted publickey for deploy`,
			when: "2026-03-17 21:42:10", sev: "Info", host: "web-1", app: "sshd", pid: "4242",
			msg: "Accepted publickey for deploy",
		},
		{
			name: "RFC 3164 with a priority",
			line: `<38>Mar 17 21:42:10 web-1 sshd[4242]: Failed password for root`,
			when: "03-17 21:42:10", layout: "01-02 15:04:05", local: true,
			sev: "Info", host: "web-1", app: "sshd", pid: "4242",
			msg: "Failed password for root",
		},
		{
			name: "rsyslog traditional file format, no priority",
			line: `Sep 18 08:05:13 nbb-ad-01.vms.nbb.nod Microsoft-Windows-Security-Auditing[756]: An account was logged on.`,
			when: "2026-09-18 08:05:13", sev: "Notice",
			host: "nbb-ad-01.vms.nbb.nod", app: "Microsoft-Windows-Security-Auditing", pid: "756",
			msg: "An account was logged on.",
		},
		{
			name: "rsyslog FileFormat, ISO stamp",
			line: `2026-09-18T08:05:13.123456+02:00 web-1 sshd[4242]: Accepted publickey for deploy`,
			when: "2026-09-18 06:05:13", sev: "Notice", host: "web-1", app: "sshd", pid: "4242",
			msg: "Accepted publickey for deploy",
		},
		{
			name: "systemd, journalctl short",
			line: `Sep 18 08:05:13 web-1 systemd[1]: Started Daily apt upgrade.`,
			when: "2026-09-18 08:05:13", sev: "Notice", host: "web-1", app: "systemd", pid: "1",
			msg: "Started Daily apt upgrade.",
		},

		// --- application loggers -------------------------------------------
		{
			name: "Go standard logger",
			line: `2026/03/17 21:42:10 starting worker pool`,
			when: "2026-03-17 21:42:10", sev: "Notice", msg: "starting worker pool",
		},
		{
			name: "nginx error log",
			line: `2026/03/17 21:42:10 [error] 1234#0: *1 connect() failed while connecting to upstream`,
			when: "2026-03-17 21:42:10", sev: "Error",
		},
		{
			name: "Apache error log",
			line: `[Mon Mar 17 21:42:10.123456 2026] [core:error] [pid 1234] AH00037: Symbolic link not allowed`,
			when: "2026-03-17 21:42:10", sev: "Error", pid: "1234",
			msg: "AH00037: Symbolic link not allowed",
		},
		{
			name: "Apache/nginx access log",
			line: `198.51.100.7 - - [17/Mar/2026:21:42:10 +0000] "GET /health HTTP/1.1" 500 172 "-" "curl/8.5.0"`,
			when: "2026-03-17 21:42:10", sev: "Error", host: "198.51.100.7",
		},
		{
			name: "Kubernetes klog",
			line: `I0317 21:42:10.123456    1234 controller.go:212] Starting workers`,
			when: "2026-03-17 21:42:10", sev: "Info", app: "controller.go", pid: "1234",
			msg: "Starting workers",
		},
		{
			name: "Android logcat, threadtime",
			line: `03-17 21:42:10.123  1234  5678 E ActivityManager: ANR in com.example.app`,
			when: "2026-03-17 21:42:10", sev: "Error", app: "ActivityManager", pid: "1234",
			msg: "ANR in com.example.app",
		},
		{
			name: "Squid, epoch at the front",
			line: `1774388530.123    123 198.51.100.7 TCP_MISS/200 4021 GET http://example.com/`,
			when: "2026", layout: "2006", sev: "Notice",
		},
		{
			name: "Java, logback",
			line: `2026-03-17 21:42:10,123 [http-nio-8080-exec-3] ERROR c.e.Service - boom`,
			when: "2026-03-17 21:42:10", sev: "Error",
		},
		{
			name: "Python, logging module",
			line: `2026-03-17 21:42:10,123 - mymodule - ERROR - connection lost`,
			when: "2026-03-17 21:42:10", sev: "Error",
		},
		{
			name: "Serilog, three-letter level",
			line: `2026-03-17 21:42:10.123 +02:00 [INF] Now listening on http://localhost:5000`,
			when: "2026-03-17 19:42:10", sev: "Info",
		},
		{
			name: "MySQL error log",
			line: `2026-03-17T21:42:10.123456Z 0 [Warning] [MY-010068] CA certificate is self signed`,
			when: "2026-03-17 21:42:10", sev: "Warning",
		},
		{
			name: "zap, console encoder",
			line: "2026-03-17T21:42:10.123+0200\tINFO\tpkg/file.go:42\tserver started",
			when: "2026-03-17 19:42:10", sev: "Info",
		},
		{
			name: "Docker, --timestamps",
			line: `2026-03-17T21:42:10.123456789Z Starting container`,
			when: "2026-03-17 21:42:10", sev: "Notice", msg: "Starting container",
		},
		{
			name: "Ruby and Rails logger",
			line: `I, [2026-03-17T21:42:10.123456 #1234]  INFO -- : Completed 200 OK`,
			when: "2026-03-17 21:42:10", sev: "Info",
		},
		{
			name: ".NET console, level then category",
			line: `info: Microsoft.Hosting.Lifetime[0] Now listening`,
			when: "", sev: "Info",
		},

		// --- structured ----------------------------------------------------
		{
			name: "JSON, numeric level and epoch milliseconds",
			line: `{"level":50,"time":1774388532123,"msg":"pool exhausted","service":"api"}`,
			when: "2026", layout: "2006", sev: "Error", app: "api", msg: "pool exhausted",
		},
		{
			name: "JSON, string level and RFC 3339",
			line: `{"time":"2026-03-17T21:42:10Z","level":"warn","msg":"disk almost full","host":"web-1"}`,
			when: "2026-03-17 21:42:10", sev: "Warning", host: "web-1", msg: "disk almost full",
		},
		{
			name: "logfmt",
			line: `ts=2026-03-17T21:42:10Z level=error msg="connection refused" err="dial tcp"`,
			when: "2026-03-17 21:42:10", sev: "Error",
		},

		// --- what must NOT be recognised -----------------------------------
		{
			name: "a sentence with a colon in it",
			line: `2026-03-17 21:42:10 something happened here: it failed`,
			when: "2026-03-17 21:42:10", sev: "Notice",
			msg: "something happened here: it failed",
		},
		{
			name: "a level word followed by a colon",
			line: `2026-03-17 21:42:10 ERROR: something failed`,
			when: "2026-03-17 21:42:10", sev: "Error", msg: "ERROR: something failed",
		},
		{
			name: "a stack trace line",
			line: "\tat java.base/java.lang.Thread.run(Thread.java:840)",
			when: "", sev: "Notice",
		},
		{
			name: "a line that says nothing",
			line: `just some text with no shape at all`,
			when: "", sev: "Notice", msg: "just some text with no shape at all",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, msgs := readFormat(t, c.line+"\n", models.ImportFormat{Mode: models.ImportAuto})
			if len(msgs) != 1 {
				t.Fatalf("got %d messages, want 1", len(msgs))
			}
			m := msgs[0]

			layout := c.layout
			if layout == "" {
				layout = defaultLayout
			}
			if c.when == "" {
				// No timestamp in the line: the message keeps the moment it was
				// read, which is today rather than the line's own year.
				if m.Timestamp.UTC().Format("2006-01-02") != time.Now().UTC().Format("2006-01-02") {
					t.Errorf("read a timestamp where the line has none: %s", m.Timestamp)
				}
			} else {
				at := m.Timestamp.UTC()
				if c.local {
					at = m.Timestamp.In(time.Local)
				}
				if got := at.Format(layout); got != c.when {
					t.Errorf("time = %s, want %s", got, c.when)
				}
			}

			if m.SeverityLabel != c.sev {
				t.Errorf("severity = %q, want %q", m.SeverityLabel, c.sev)
			}
			if m.Hostname != c.host {
				t.Errorf("hostname = %q, want %q", m.Hostname, c.host)
			}
			if m.AppName != c.app {
				t.Errorf("app = %q, want %q", m.AppName, c.app)
			}
			if m.ProcID != c.pid {
				t.Errorf("pid = %q, want %q", m.ProcID, c.pid)
			}
			if c.msg != "" && m.Message != c.msg {
				t.Errorf("message = %q, want %q", m.Message, c.msg)
			}
		})
	}
}
