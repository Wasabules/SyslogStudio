package importer

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func readAll(t *testing.T, path string, limit int) (Result, []models.SyslogMessage) {
	t.Helper()
	var msgs []models.SyslogMessage
	res, err := Read(Options{Path: path, Year: 2026, Location: time.UTC, Limit: limit},
		func(m models.SyslogMessage) bool { msgs = append(msgs, m); return true })
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return res, msgs
}

// A captured syslog file is the thing this application already parses off the
// wire, so nothing about it should be guessed.
func TestRead_SyslogLinesGoThroughTheWireParser(t *testing.T) {
	p := write(t, "capture.log", strings.Join([]string{
		"<131>1 2026-03-17T21:42:10Z vpn-gw-01 ipsec 4242 - - tunnel torn down",
		"<134>1 2026-03-17T21:42:11Z web-1 sshd 22 - - Accepted publickey for bob",
	}, "\n"))

	res, msgs := readAll(t, p, 0)

	if res.Syslog != 2 {
		t.Fatalf("Syslog = %d, want 2", res.Syslog)
	}
	if res.LevelDetected != 0 || res.TimeDetected != 0 {
		t.Errorf("guessed at a line that said what it was: time=%d level=%d",
			res.TimeDetected, res.LevelDetected)
	}
	if msgs[0].Hostname != "vpn-gw-01" || msgs[0].AppName != "ipsec" {
		t.Errorf("host/app lost: %q / %q", msgs[0].Hostname, msgs[0].AppName)
	}
	if msgs[0].SeverityLabel != "Error" {
		t.Errorf("severity = %q, want Error (PRI 131)", msgs[0].SeverityLabel)
	}
	if got := msgs[0].Timestamp.UTC().Format(time.RFC3339); got != "2026-03-17T21:42:10Z" {
		t.Errorf("timestamp = %s, want the one in the line", got)
	}
}

// The point of the feature: a plain application log must sort by severity.
func TestRead_PlainLinesGetTheirLevelAndTime(t *testing.T) {
	p := write(t, "app.log", strings.Join([]string{
		"2026-03-17 21:42:10 INFO  starting up",
		"2026-03-17 21:42:11 WARN  disk almost full",
		"2026-03-17 21:42:12 ERROR connection refused",
		"2026-03-17 21:42:13 DEBUG retrying",
	}, "\n"))

	res, msgs := readAll(t, p, 0)

	if res.Imported != 4 {
		t.Fatalf("Imported = %d, want 4", res.Imported)
	}
	if res.TimeDetected != 4 || res.LevelDetected != 4 {
		t.Fatalf("detected time=%d level=%d, want 4 and 4", res.TimeDetected, res.LevelDetected)
	}
	want := map[string]int{"Info": 1, "Warning": 1, "Error": 1, "Debug": 1}
	for label, n := range want {
		if res.BySeverity[label] != n {
			t.Errorf("BySeverity[%s] = %d, want %d", label, res.BySeverity[label], n)
		}
	}
	// Without detection every one of these would be Notice stamped at import
	// time, which is the state the issue describes as useless.
	if msgs[2].SeverityLabel != "Error" {
		t.Errorf("third line severity = %q", msgs[2].SeverityLabel)
	}
	if got := msgs[0].Timestamp.UTC().Format(time.RFC3339); got != "2026-03-17T21:42:10Z" {
		t.Errorf("first line timestamp = %s", got)
	}
}

// A line that says nothing keeps the parser's fallback rather than being
// invented into something.
func TestRead_UnrecognisableLinesAreKeptAsThemselves(t *testing.T) {
	p := write(t, "odd.log", "just some text\nand another line\n")
	res, msgs := readAll(t, p, 0)

	if res.Imported != 2 {
		t.Fatalf("Imported = %d, want 2", res.Imported)
	}
	if res.TimeDetected != 0 || res.LevelDetected != 0 {
		t.Errorf("claimed to recognise something: time=%d level=%d", res.TimeDetected, res.LevelDetected)
	}
	if msgs[0].Message != "just some text" {
		t.Errorf("Message = %q, want the line unchanged", msgs[0].Message)
	}
}

// Imported lines must be visibly not received traffic, so they can be told
// apart and filtered out.
func TestRead_MarksTheSource(t *testing.T) {
	p := write(t, "nightly.log", "2026-03-17 21:42:10 INFO done\n")
	_, msgs := readAll(t, p, 0)

	if msgs[0].Protocol != "file" {
		t.Errorf("Protocol = %q, want \"file\"", msgs[0].Protocol)
	}
	if msgs[0].SourceIP != "nightly.log" {
		t.Errorf("SourceIP = %q, want the file name", msgs[0].SourceIP)
	}
}

// The raw column must show the line as it was in the file, not the remains
// after the timestamp was taken off the front.
func TestRead_KeepsTheOriginalLine(t *testing.T) {
	line := "2026-03-17 21:42:10 ERROR connection refused"
	p := write(t, "raw.log", line+"\n")
	_, msgs := readAll(t, p, 0)

	if msgs[0].RawMessage != line {
		t.Errorf("RawMessage = %q, want the whole line", msgs[0].RawMessage)
	}
	if msgs[0].Message != "ERROR connection refused" {
		t.Errorf("Message = %q", msgs[0].Message)
	}
}

func TestRead_SkipsBlankLinesQuietly(t *testing.T) {
	p := write(t, "gaps.log", "INFO one\n\n\nINFO two\n")
	res, _ := readAll(t, p, 0)

	if res.Imported != 2 {
		t.Fatalf("Imported = %d, want 2", res.Imported)
	}
	if res.Blank != 2 {
		t.Errorf("Blank = %d, want 2", res.Blank)
	}
	if res.LinesRead != 4 {
		t.Errorf("LinesRead = %d, want 4", res.LinesRead)
	}
}

// A partial import must never be mistaken for a complete one.
func TestRead_SaysWhenItStoppedEarly(t *testing.T) {
	var lines []string
	for i := 0; i < 50; i++ {
		lines = append(lines, "INFO line")
	}
	p := write(t, "many.log", strings.Join(lines, "\n"))

	res, msgs := readAll(t, p, 10)
	if !res.Stopped {
		t.Error("Stopped is false after hitting the limit")
	}
	if res.Imported != 10 || len(msgs) != 10 {
		t.Errorf("Imported = %d, messages = %d, want 10", res.Imported, len(msgs))
	}
}

// The caller stops the read by refusing a message, which is how a ring buffer
// enforces its own ceiling without this package knowing about one.
func TestRead_StopsWhenTheCallerRefuses(t *testing.T) {
	p := write(t, "many.log", strings.Repeat("INFO line\n", 100))
	n := 0
	res, err := Read(Options{Path: p, Year: 2026, Location: time.UTC},
		func(models.SyslogMessage) bool { n++; return n < 5 })
	if err != nil {
		t.Fatal(err)
	}
	if !res.Stopped || n != 5 {
		t.Fatalf("stopped=%v after %d messages, want true after 5", res.Stopped, n)
	}
}

// Rotated logs are almost always gzipped; asking the user to gunzip first would
// be a chore the application can simply not impose.
func TestRead_ReadsGzip(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("2026-03-17 21:42:10 ERROR compressed\n"))
	zw.Close()

	p := filepath.Join(t.TempDir(), "rotated.log.gz")
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	res, msgs := readAll(t, p, 0)
	if res.Imported != 1 {
		t.Fatalf("Imported = %d, want 1", res.Imported)
	}
	if msgs[0].SeverityLabel != "Error" {
		t.Errorf("severity = %q", msgs[0].SeverityLabel)
	}
}

func TestRead_RefusesAFileThatIsNotGzipDespiteItsName(t *testing.T) {
	p := write(t, "lying.log.gz", "this is plain text\n")
	_, err := Read(Options{Path: p}, func(models.SyslogMessage) bool { return true })
	if err == nil {
		t.Fatal("a plain file named .gz was accepted as gzip")
	}
	if !strings.Contains(err.Error(), "gzip") {
		t.Errorf("error does not say what is wrong: %v", err)
	}
}

func TestRead_ReportsAMissingFile(t *testing.T) {
	_, err := Read(Options{Path: filepath.Join(t.TempDir(), "absent.log")},
		func(models.SyslogMessage) bool { return true })
	if err == nil {
		t.Fatal("a missing file was read successfully")
	}
}

// The preview exists so an inference can be seen and rejected before anything
// is imported.
func TestPreviewFile_SamplesAndReportsWhatWasInferred(t *testing.T) {
	p := write(t, "big.log", strings.Repeat("2026-03-17 21:42:10 WARN something\n", 1000))

	pv, err := PreviewFile(Options{Path: p, Year: 2026, Location: time.UTC})
	if err != nil {
		t.Fatal(err)
	}
	if len(pv.Messages) != previewLines {
		t.Fatalf("preview has %d messages, want %d", len(pv.Messages), previewLines)
	}
	if !pv.Result.Stopped {
		t.Error("a preview of a longer file does not report that it stopped")
	}
	if pv.Result.LevelDetected != previewLines {
		t.Errorf("LevelDetected = %d, want %d", pv.Result.LevelDetected, previewLines)
	}
}
