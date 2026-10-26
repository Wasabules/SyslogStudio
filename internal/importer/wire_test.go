package importer

import (
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/syslog"
)

// What devices actually send, each read as the sender meant it.
func TestWireReader_ReadsWhatIsNotQuiteSyslog(t *testing.T) {
	w := NewWireReader()
	local := func(s string) time.Time {
		t, err := time.ParseInLocation("2006-01-02 15:04:05.000", s, time.Local)
		if err != nil {
			panic(err)
		}
		return t
	}
	utc := func(s string) time.Time {
		t, err := time.Parse(time.RFC3339Nano, s)
		if err != nil {
			panic(err)
		}
		return t
	}
	for _, tc := range []struct {
		name, raw            string
		sev                  models.Severity
		host, app, proc, msg string
		at                   time.Time // zero: not checked
		atClock              string    // "Jan 2 15:04:05.000", for a stamp with no year
	}{
		{
			name: "rsyslog's forwarding format: RFC 3339, no version",
			raw:  "<30>2026-10-27T09:14:02.123+01:00 nas-01 smbd[812]: connection from 10.0.0.9",
			sev:  models.SevInformational, host: "nas-01", app: "smbd", proc: "812", msg: "connection from 10.0.0.9",
			at: utc("2026-10-27T08:14:02.123Z"),
		},
		{
			name: "an ISO stamp, a tag and no host",
			raw:  "<14>2026-10-27T09:14:02Z backup[44]: done in 12 s",
			sev:  models.SevInformational, app: "backup", proc: "44", msg: "done in 12 s",
			at: utc("2026-10-27T09:14:02Z"),
		},
		{
			name: "a level word does not override the priority",
			raw:  "<14>2026-10-27T09:14:02Z web-1 app: ERROR upstream timed out",
			sev:  models.SevInformational, host: "web-1", app: "app", msg: "ERROR upstream timed out",
		},
		{
			name: "FortiGate: key=value, the date and time in two fields, the level declared",
			raw:  `<189>date=2026-10-27 time=09:14:02 devname="FGT60F" level="warning" logid="0100032002" msg="Admin login failed"`,
			sev:  models.SevWarning, host: "FGT60F", msg: "Admin login failed logid=0100032002",
			at: local("2026-10-27 09:14:02.000"),
		},
		{
			name: "Cisco IOS: a sequence number and a starred stamp",
			raw:  "<187>123: *Oct 27 09:14:02.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down",
			sev:  models.SevError, app: "%LINK-3-UPDOWN", msg: "Interface Gi0/1, changed state to down",
			atClock: "Oct 27 09:14:02.123",
		},
		{
			name: "Cisco IOS: the host, a year and a zone",
			raw:  "<189>124: R1: Oct 27 2026 09:14:02 CET: %SYS-5-CONFIG_I: Configured from console by admin",
			sev:  models.SevNotice, host: "R1", app: "%SYS-5-CONFIG_I", msg: "Configured from console by admin",
			at: local("2026-10-27 09:14:02.000"),
		},
		{
			name: "Cisco IOS with no timestamp",
			raw:  "<187>125: %LINK-3-UPDOWN: Interface Gi0/2, changed state to down",
			sev:  models.SevError, app: "%LINK-3-UPDOWN", msg: "Interface Gi0/2, changed state to down",
		},
		{
			name: "Cisco ASA with a year",
			raw:  "<166>Oct 27 2026 09:14:02: %ASA-6-302013: Built outbound TCP connection 1 for outside",
			sev:  models.SevInformational, app: "%ASA-6-302013", msg: "Built outbound TCP connection 1 for outside",
			at: local("2026-10-27 09:14:02.000"),
		},
		{
			name: "Cisco ASA with its device id",
			raw:  "<164>Oct 27 2026 09:14:02 FW-01 : %ASA-4-106023: Deny tcp src outside:10.0.0.1",
			sev:  models.SevWarning, host: "FW-01", app: "%ASA-4-106023", msg: "Deny tcp src outside:10.0.0.1",
		},
		{
			name: "JSON after the priority: the declared level wins",
			raw:  `<14>{"level":"error","time":"2026-10-27T09:14:02Z","msg":"disk full","host":"app-3"}`,
			sev:  models.SevError, host: "app-3", msg: "disk full",
			at: utc("2026-10-27T09:14:02Z"),
		},
		{
			name: "JSON with no priority",
			raw:  `{"level":"warn","msg":"queue depth 812","service":"worker"}`,
			sev:  models.SevWarning, app: "worker", msg: "queue depth 812",
		},
		{
			name: "no priority: a stamp and a level word in front",
			raw:  "2026-10-27 09:14:02 ERROR motion detection failed on channel 2",
			sev:  models.SevError, msg: "ERROR motion detection failed on channel 2",
			at: local("2026-10-27 09:14:02.000"),
		},
		{
			name: "no priority: a level word inside a sentence is just a word",
			raw:  "backup finished, error: none",
			sev:  models.SevNotice, msg: "backup finished, error: none",
		},
		{
			name: "no priority: a BSD line as written to disk",
			raw:  "Oct 27 09:14:02 nas-01 smbd[812]: connection from 10.0.0.9",
			sev:  models.SevNotice, host: "nas-01", app: "smbd", proc: "812", msg: "connection from 10.0.0.9",
			atClock: "Oct 27 09:14:02.000",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := w.Read([]byte(tc.raw), "10.0.0.9", "UDP")
			if m.Severity != tc.sev || m.SeverityLabel != models.SeverityToLabel(tc.sev) {
				t.Errorf("severity %v (%s), want %v", m.Severity, m.SeverityLabel, tc.sev)
			}
			if m.Hostname != tc.host || m.AppName != tc.app || m.ProcID != tc.proc || m.Message != tc.msg {
				t.Errorf("host=%q app=%q proc=%q msg=%q\nwant host=%q app=%q proc=%q msg=%q",
					m.Hostname, m.AppName, m.ProcID, m.Message, tc.host, tc.app, tc.proc, tc.msg)
			}
			if !tc.at.IsZero() && !m.Timestamp.Equal(tc.at) {
				t.Errorf("timestamp %v, want %v", m.Timestamp, tc.at)
			}
			if tc.atClock != "" {
				if got := m.Timestamp.In(time.Local).Format("Jan 2 15:04:05.000"); got != tc.atClock {
					t.Errorf("timestamp %v, want %s", m.Timestamp, tc.atClock)
				}
			}
			if m.RawMessage != tc.raw || m.SourceIP != "10.0.0.9" || m.Protocol != "UDP" || m.ID == "" {
				t.Errorf("the message lost what it arrived as: %+v", m)
			}
		})
	}
}

// A message whose header is the RFCs' is exactly what the wire parser makes
// of it: reading again is for what it could only keep as text.
func TestWireReader_LeavesStandardMessagesAlone(t *testing.T) {
	w := NewWireReader()
	for _, raw := range []string{
		"<165>1 2026-10-27T09:14:02.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\"] An application event",
		"<14>1 - - - - - - hello",
		"<38>Oct 27 09:14:02 webserver nginx: GET /index.html 200",
		"<38>Oct  7 09:14:02 webserver nginx[12]: {\"level\":\"error\"}",
		"<134>Oct 27 09:14:02 dhcp: lease 10.0.0.50 assigned",
		"<13>Oct 27 09:14:02 host",
	} {
		got := w.Read([]byte(raw), "10.0.0.9", "UDP")
		want := syslog.Parse([]byte(raw), "10.0.0.9", "UDP")
		// A message with no timestamp is stamped with its arrival, which is a
		// moment apart from one reading to the other.
		arrival := func(m models.SyslogMessage) bool { return m.Timestamp.Equal(m.ReceivedAt) }
		if arrival(got) != arrival(want) || (!arrival(want) && !got.Timestamp.Equal(want.Timestamp)) {
			t.Errorf("%s: timestamp %v, the wire parser's %v", raw, got.Timestamp, want.Timestamp)
		}
		got.ID, got.ReceivedAt, want.ID, want.ReceivedAt = "", time.Time{}, "", time.Time{}
		got.Timestamp, want.Timestamp = time.Time{}, time.Time{}
		if got != want {
			t.Errorf("%s\n  read again: %+v\n  wire:       %+v", raw, got, want)
		}
	}
}

// A file of lines as rsyslog forwards them is read as the wire reads them:
// one definition of a line, wherever it comes from.
func TestRead_FileOfForwardedLines(t *testing.T) {
	p := write(t, "forwarded.log", strings.Join([]string{
		"<30>2026-10-27T09:14:02.123+01:00 nas-01 smbd[812]: connection from 10.0.0.9",
		`<189>date=2026-10-27 time=09:14:03 devname="FGT60F" level="error" msg="IPsec phase 1 failed"`,
	}, "\n"))
	res, msgs := readAll(t, p, 0)
	if len(msgs) != 2 || res.Syslog != 2 {
		t.Fatalf("read %d messages, %d as syslog", len(msgs), res.Syslog)
	}
	if msgs[0].Hostname != "nas-01" || msgs[0].AppName != "smbd" || msgs[0].Message != "connection from 10.0.0.9" {
		t.Errorf("rsyslog line: %+v", msgs[0])
	}
	if msgs[1].Hostname != "FGT60F" || msgs[1].Severity != models.SevError {
		t.Errorf("FortiGate line: %+v", msgs[1])
	}
}
