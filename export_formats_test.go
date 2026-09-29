package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/importer"
	"SyslogStudio/internal/models"
)

func exportSample() []models.SyslogMessage {
	at := time.Date(2026, 3, 17, 21, 42, 10, 0, time.UTC)
	return []models.SyslogMessage{
		{
			ID: "1", Timestamp: at, ReceivedAt: at,
			Severity: models.SevError, SeverityLabel: "Error",
			Facility: models.FacLocal0, FacilityLabel: "local0",
			Hostname: "vpn-gw-01", AppName: "ipsec", ProcID: "4242",
			Message: "IKE_SA rekey failed", SourceIP: "10.0.0.7", Protocol: "TCP",
		},
		{
			ID: "2", Timestamp: at.Add(time.Second), ReceivedAt: at.Add(time.Second),
			Severity: models.SevInformational, SeverityLabel: "Info",
			Facility: models.FacUser, FacilityLabel: "user",
			Hostname: "web-1", AppName: "sshd",
			// A message that would break a line-based format if it were let
			// through as it stands.
			Message: "Accepted publickey\nfor deploy", SourceIP: "10.0.0.9", Protocol: "UDP",
		},
	}
}

func writeTo(t *testing.T, name, format string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := writeExport(path, format, exportSample(), time.UTC); err != nil {
		t.Fatalf("writeExport(%s): %v", format, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// --- NDJSON ------------------------------------------------------------------

func TestExport_NDJSONIsOneObjectPerLine(t *testing.T) {
	out := writeTo(t, "out.ndjson", formatNDJSON)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")

	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2 — a message with a newline in it must not become two records", len(lines))
	}

	var first exportRecord
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("line 1 is not JSON: %v", err)
	}
	if first.SeverityLabel != "Error" || first.Hostname != "vpn-gw-01" || first.ProcID != "4242" {
		t.Errorf("fields lost: %+v", first)
	}
	if first.Timestamp != "2026-03-17T21:42:10Z" {
		t.Errorf("timestamp = %q, want RFC 3339", first.Timestamp)
	}

	var second exportRecord
	if err := json.Unmarshal([]byte(lines[1]), &second); err != nil {
		t.Fatalf("line 2 is not JSON: %v", err)
	}
	// The newline survives inside the value, which is the whole reason to use
	// JSON rather than another line-based format.
	if second.Message != "Accepted publickey\nfor deploy" {
		t.Errorf("message = %q, want the newline kept inside the field", second.Message)
	}
}

// --- syslog ------------------------------------------------------------------

// The point of writing syslog is that it can be read back. Ours is the parser
// nearest to hand, and if it cannot read what we wrote, nothing else will.
func TestExport_RFC5424RoundTripsThroughTheImporter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay.log")
	if err := writeExport(path, formatRFC5424, exportSample(), time.UTC); err != nil {
		t.Fatal(err)
	}

	var back []models.SyslogMessage
	res, err := importer.Read(
		importer.Options{Path: path, Year: 2026, Location: time.UTC,
			Format: models.ImportFormat{Mode: models.ImportSyslog}},
		func(m models.SyslogMessage) bool { back = append(back, m); return true })
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}

	if res.Imported != 2 || res.Syslog != 2 {
		t.Fatalf("read back %d messages (%d with a priority), want 2 and 2", res.Imported, res.Syslog)
	}
	if back[0].SeverityLabel != "Error" || back[0].FacilityLabel != "local0" {
		t.Errorf("priority lost: %s / %s", back[0].SeverityLabel, back[0].FacilityLabel)
	}
	if back[0].Hostname != "vpn-gw-01" || back[0].AppName != "ipsec" || back[0].ProcID != "4242" {
		t.Errorf("origin lost: %q / %q / %q", back[0].Hostname, back[0].AppName, back[0].ProcID)
	}
	if back[0].Message != "IKE_SA rekey failed" {
		t.Errorf("message = %q", back[0].Message)
	}
	if got := back[0].Timestamp.UTC().Format(time.RFC3339); got != "2026-03-17T21:42:10Z" {
		t.Errorf("timestamp = %s", got)
	}
	// The embedded newline had to go somewhere, and a space is the only place
	// it can go in a format that ends a record at one.
	if strings.Contains(back[1].Message, "\n") || !strings.Contains(back[1].Message, "for deploy") {
		t.Errorf("second message = %q", back[1].Message)
	}
}

func TestExport_RFC3164RoundTripsThroughTheImporter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "replay-bsd.log")
	if err := writeExport(path, formatRFC3164, exportSample(), time.UTC); err != nil {
		t.Fatal(err)
	}

	var back []models.SyslogMessage
	if _, err := importer.Read(
		importer.Options{Path: path, Year: 2026, Location: time.UTC,
			Format: models.ImportFormat{Mode: models.ImportSyslog}},
		func(m models.SyslogMessage) bool { back = append(back, m); return true }); err != nil {
		t.Fatal(err)
	}

	if len(back) != 2 {
		t.Fatalf("read back %d messages, want 2", len(back))
	}
	if back[0].SeverityLabel != "Error" || back[0].Hostname != "vpn-gw-01" {
		t.Errorf("got %q / %q", back[0].SeverityLabel, back[0].Hostname)
	}
	if back[0].AppName != "ipsec" || back[0].ProcID != "4242" {
		t.Errorf("tag lost: %q[%q]", back[0].AppName, back[0].ProcID)
	}
}

func TestExport_SyslogFillsEmptyFieldsWithADash(t *testing.T) {
	msgs := []models.SyslogMessage{{
		Timestamp: time.Date(2026, 3, 17, 21, 42, 10, 0, time.UTC),
		Severity:  models.SevNotice, SeverityLabel: "Notice",
		Facility: models.FacUser, Message: "bare",
	}}
	path := filepath.Join(t.TempDir(), "bare.log")
	if err := writeExport(path, formatRFC5424, msgs, time.UTC); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	line := strings.TrimSpace(string(data))

	// <13>1 <time> HOST APP PROCID MSGID SD MSG, with a dash for each absent
	// field. Counted by position rather than by substring: consecutive dashes
	// share their spaces, so counting " - " finds half of them.
	if !strings.HasPrefix(line, "<13>1 ") {
		t.Errorf("line = %q, want a priority and a version", line)
	}
	fields := strings.Split(line, " ")
	if len(fields) < 8 {
		t.Fatalf("line = %q, want eight fields", line)
	}
	for i := 2; i <= 6; i++ {
		if fields[i] != "-" {
			t.Errorf("field %d = %q, want a dash for an absent field (%q)", i, fields[i], line)
		}
	}
	if fields[7] != "bare" {
		t.Errorf("message = %q", fields[7])
	}
}

// --- HTML --------------------------------------------------------------------

func TestExport_HTMLEscapesTheMessage(t *testing.T) {
	msgs := []models.SyslogMessage{{
		Timestamp: time.Now(), Severity: models.SevError, SeverityLabel: "Error",
		Hostname: "web-1", AppName: "nginx",
		// A log line is attacker-controlled text, and this report is opened in
		// a browser by someone who did not write it.
		Message: `<script>alert("xss")</script> & <img src=x onerror=1>`,
	}}
	path := filepath.Join(t.TempDir(), "report.html")
	if err := writeExport(path, formatHTML, msgs, time.UTC); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	out := string(data)

	if strings.Contains(out, "<script>alert") || strings.Contains(out, "onerror=1>") {
		t.Fatal("a message was written into the report as markup")
	}
	if !strings.Contains(out, "&lt;script&gt;") || !strings.Contains(out, "&amp;") {
		t.Error("the message is not in the report at all")
	}
	if !strings.Contains(out, "#ff8800") {
		t.Error("the severity colour is missing, so the report does not read like the screen")
	}
	if !strings.Contains(out, "<!DOCTYPE html>") || !strings.Contains(out, "</html>") {
		t.Error("the report is not a whole document")
	}
}

func TestExport_EveryFormatNamesItsFile(t *testing.T) {
	cases := map[string]string{
		formatCSV:     ".csv",
		formatText:    ".txt",
		formatNDJSON:  ".ndjson",
		formatRFC5424: ".log",
		formatRFC3164: ".log",
		formatHTML:    ".html",
		"something":   ".txt",
	}
	for format, ext := range cases {
		name, filters := exportFile(format, "syslog_export")
		if !strings.HasSuffix(name, ext) {
			t.Errorf("%s suggests %q, want a %s file", format, name, ext)
		}
		if len(filters) == 0 {
			t.Errorf("%s offers no dialog filter", format)
		}
	}
}
