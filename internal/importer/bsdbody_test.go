package importer

import (
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

// The file format rsyslog writes by default (#50).
//
// The priority exists only on the wire, so a captured file has a timestamp, a
// host and a tag and nothing that announces itself as syslog. Read as free
// text, the host and the tag stayed inside the message and the Hostname and
// App columns were empty — which is exactly what makes such a file impossible
// to filter, and what the reporter saw.

func TestAuto_ReadsTheHostAndTagOfAPriorityLessSyslogLine(t *testing.T) {
	// The reporter's own line, verbatim.
	const content = "Sep 18 08:05:13 nbb-ad-01.vms.nbb.nod Microsoft-Windows-Security-Auditing[756]: An account was successfully logged on.\n" +
		"Sep 18 08:05:32 nbb-ad-01.vms.nbb.nod Microsoft-Windows-GroupPolicy[1668]: Completed periodic policy processing\n"

	res, msgs := readFormat(t, content, models.ImportFormat{Mode: models.ImportAuto})

	if res.HostDetected != 2 || res.TimeDetected != 2 {
		t.Fatalf("host=%d time=%d, want 2 and 2", res.HostDetected, res.TimeDetected)
	}
	if msgs[0].Hostname != "nbb-ad-01.vms.nbb.nod" {
		t.Errorf("Hostname = %q", msgs[0].Hostname)
	}
	if msgs[0].AppName != "Microsoft-Windows-Security-Auditing" || msgs[0].ProcID != "756" {
		t.Errorf("app/pid = %q / %q", msgs[0].AppName, msgs[0].ProcID)
	}
	// The message must no longer carry the host and the tag: that text in front
	// of it is what the reporter read as a prefix added by the importer.
	if msgs[0].Message != "An account was successfully logged on." {
		t.Errorf("Message = %q", msgs[0].Message)
	}
	if strings.Contains(msgs[0].Message, "nbb-ad-01") {
		t.Error("the hostname is still inside the message")
	}
}

// rsyslog's other stock template, and the one syslog-ng writes: the same body
// behind an ISO 8601 timestamp.
func TestAuto_ReadsTheSameBodyBehindAnISOTimestamp(t *testing.T) {
	const content = "2026-09-18T08:05:13.123456+02:00 web-1 sshd[4242]: Accepted publickey for deploy\n"
	_, msgs := readFormat(t, content, models.ImportFormat{Mode: models.ImportAuto})

	if msgs[0].Hostname != "web-1" || msgs[0].AppName != "sshd" || msgs[0].ProcID != "4242" {
		t.Fatalf("got %q / %q / %q", msgs[0].Hostname, msgs[0].AppName, msgs[0].ProcID)
	}
	if msgs[0].Message != "Accepted publickey for deploy" {
		t.Errorf("Message = %q", msgs[0].Message)
	}
}

// A tag with no pid is the more common half of RFC 3164.
func TestAuto_ReadsATagWithoutAProcessID(t *testing.T) {
	const content = "Mar 17 21:44:00 db-2 postgres: checkpoint complete\n"
	_, msgs := readFormat(t, content, models.ImportFormat{Mode: models.ImportAuto})

	if msgs[0].Hostname != "db-2" || msgs[0].AppName != "postgres" {
		t.Fatalf("got %q / %q", msgs[0].Hostname, msgs[0].AppName)
	}
	if msgs[0].ProcID != "" {
		t.Errorf("ProcID = %q, want empty", msgs[0].ProcID)
	}
}

// The guard that keeps this from eating ordinary application logs. Each of
// these lines must come back with no hostname at all.
func TestAuto_DoesNotInventAHostOnAnApplicationLog(t *testing.T) {
	lines := []struct{ name, line string }{
		{"no tag at all", "2026-03-17 21:42:01 INFO worker pool started with 16 threads"},
		{"a level then a colon", "2026-03-17 21:42:40 WARN queue: depth 812 above soft limit"},
		{"a level in brackets", "2026-03-17 21:42:10 [ERROR] connection refused to db-2"},
		{"a sentence with a colon", "2026-03-17 21:43:00 something happened here: it failed"},
		{"a java logger line", "2026-03-17 21:42:10,123 [http-nio-8080-exec-3] ERROR c.e.Service - boom"},
		{"a url in the message", "2026-03-17 21:43:05 fetching https://example.com/api failed"},
	}
	for _, tt := range lines {
		t.Run(tt.name, func(t *testing.T) {
			_, msgs := readFormat(t, tt.line+"\n", models.ImportFormat{Mode: models.ImportAuto})
			if msgs[0].Hostname != "" {
				t.Errorf("invented hostname %q from %q", msgs[0].Hostname, tt.line)
			}
			if msgs[0].AppName != "" {
				t.Errorf("invented app %q from %q", msgs[0].AppName, tt.line)
			}
		})
	}
}

// Nothing about this may go through the wire parser's year resolution, which
// answers to the clock rather than to the format panel.
func TestAuto_APriorityLessLineStillHonoursTheYearAndZone(t *testing.T) {
	const content = "Nov  3 02:14:09 mail-1 postfix/smtpd[3121]: connect from unknown\n"
	_, msgs := readFormat(t, content, models.ImportFormat{
		Mode: models.ImportAuto, Year: 2019, Timezone: "UTC",
	})

	got := msgs[0].Timestamp.UTC()
	if got.Year() != 2019 {
		t.Errorf("year = %d, want the one the panel was given", got.Year())
	}
	if got.Format("01-02 15:04:05") != "11-03 02:14:09" {
		t.Errorf("timestamp = %s", got.Format(time.RFC3339))
	}
	if msgs[0].Hostname != "mail-1" || msgs[0].AppName != "postfix/smtpd" {
		t.Errorf("host/app = %q / %q", msgs[0].Hostname, msgs[0].AppName)
	}
}

// In syslog mode a priority-less line used to be treated as the tail of the
// one above it, so a whole rsyslog file folded into a handful of messages.
func TestSyslogMode_ReadsAFileThatHasNoPrioritiesAtAll(t *testing.T) {
	const content = "Sep 18 08:05:13 web-1 sshd[1]: first\n" +
		"Sep 18 08:05:14 web-1 sshd[2]: second\n" +
		"Sep 18 08:05:15 web-1 sshd[3]: third\n"

	res, msgs := readFormat(t, content, models.ImportFormat{
		Mode: models.ImportSyslog, JoinContinuations: true,
	})

	if res.Imported != 3 {
		t.Fatalf("Imported = %d, want 3 — each line is a message of its own", res.Imported)
	}
	if res.Joined != 0 {
		t.Errorf("Joined = %d, want 0", res.Joined)
	}
	if msgs[2].Message != "third" || msgs[2].ProcID != "3" {
		t.Errorf("third message = %q (pid %q)", msgs[2].Message, msgs[2].ProcID)
	}
}

// A line with a priority keeps going through the wire parser untouched, so
// this change cannot have moved what a real capture reads as.
func TestSyslogMode_StillPrefersARealPriority(t *testing.T) {
	const content = "<131>1 2026-03-17T21:42:10Z vpn-gw-01 ipsec 4242 - - tunnel torn down\n"
	res, msgs := readFormat(t, content, models.ImportFormat{Mode: models.ImportSyslog})

	if res.Syslog != 1 || res.HostDetected != 0 {
		t.Fatalf("Syslog = %d, HostDetected = %d, want 1 and 0 — a priority is read, not guessed",
			res.Syslog, res.HostDetected)
	}
	if msgs[0].SeverityLabel != "Error" || msgs[0].Hostname != "vpn-gw-01" {
		t.Errorf("got %q / %q", msgs[0].SeverityLabel, msgs[0].Hostname)
	}
}
