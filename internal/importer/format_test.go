package importer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

// Every one of these shapes came back from the detector as "nothing
// recognised" — measured, not assumed. That is the reason a format can be
// declared at all, so each mode is tested against the shape it exists for.

func readFormat(t *testing.T, content string, f models.ImportFormat) (Result, []models.SyslogMessage) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.log")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var msgs []models.SyslogMessage
	res, err := Read(Options{Path: p, Year: 2026, Location: time.UTC, Format: f},
		func(m models.SyslogMessage) bool { msgs = append(msgs, m); return true })
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return res, msgs
}

// --- JSON --------------------------------------------------------------------

func TestJSON_ReadsTheUsualFieldNamesWithoutBeingTold(t *testing.T) {
	const content = `{"time":"2026-03-17T21:42:10Z","level":"error","msg":"connection refused","service":"api","host":"web-1"}
{"timestamp":"2026-03-17T21:42:11Z","severity":"WARN","message":"pool at 90%","logger":"db"}
`
	res, msgs := readFormat(t, content, models.ImportFormat{Mode: models.ImportJSON})

	if res.Imported != 2 || res.Unmatched != 0 {
		t.Fatalf("Imported = %d, Unmatched = %d, want 2 and 0", res.Imported, res.Unmatched)
	}
	if res.TimeDetected != 2 || res.LevelDetected != 2 {
		t.Fatalf("time=%d level=%d, want 2 and 2", res.TimeDetected, res.LevelDetected)
	}
	if msgs[0].SeverityLabel != "Error" || msgs[0].Message != "connection refused" {
		t.Errorf("first line: %q / %q", msgs[0].SeverityLabel, msgs[0].Message)
	}
	if msgs[0].AppName != "api" || msgs[0].Hostname != "web-1" {
		t.Errorf("app/host = %q / %q, want api / web-1", msgs[0].AppName, msgs[0].Hostname)
	}
	if got := msgs[0].Timestamp.UTC().Format(time.RFC3339); got != "2026-03-17T21:42:10Z" {
		t.Errorf("timestamp = %s", got)
	}
	if msgs[1].SeverityLabel != "Warning" || msgs[1].AppName != "db" {
		t.Errorf("second line: %q / %q", msgs[1].SeverityLabel, msgs[1].AppName)
	}
	// The whole object stays available, so nothing the line carried is lost.
	if !strings.Contains(msgs[0].RawMessage, `"service":"api"`) {
		t.Errorf("raw line lost: %q", msgs[0].RawMessage)
	}
}

// pino and bunyan write the level and the time as numbers, which is exactly
// what detection cannot read.
func TestJSON_ReadsNumericLevelsAndEpochTimes(t *testing.T) {
	const content = `{"level":50,"time":1774388530123,"msg":"pool exhausted"}
{"level":30,"time":1774388531,"msg":"recovered"}
{"level":60,"time":1774388532000000,"msg":"giving up"}
`
	res, msgs := readFormat(t, content, models.ImportFormat{Mode: models.ImportJSON})

	if res.LevelDetected != 3 || res.TimeDetected != 3 {
		t.Fatalf("level=%d time=%d, want 3 and 3", res.LevelDetected, res.TimeDetected)
	}
	want := []string{"Error", "Info", "Critical"}
	for i, w := range want {
		if msgs[i].SeverityLabel != w {
			t.Errorf("message %d severity = %q, want %q", i, msgs[i].SeverityLabel, w)
		}
	}
	// Milliseconds, seconds and microseconds, told apart by magnitude alone.
	for i, m := range msgs {
		if y := m.Timestamp.UTC().Year(); y != 2026 {
			t.Errorf("message %d landed in %d, so the epoch unit was read wrong", i, y)
		}
	}
}

func TestJSON_UsesTheFieldNamesItIsGiven(t *testing.T) {
	const content = `{"when":"2026-03-17T21:42:10Z","prio":"critical","body":"disk full","unit":"cleaner"}` + "\n"
	res, msgs := readFormat(t, content, models.ImportFormat{
		Mode: models.ImportJSON, JSONTime: "when", JSONLevel: "prio",
		JSONMessage: "body", JSONApp: "unit",
	})

	if res.LevelDetected != 1 || res.TimeDetected != 1 {
		t.Fatalf("level=%d time=%d, want 1 and 1", res.LevelDetected, res.TimeDetected)
	}
	if msgs[0].SeverityLabel != "Critical" || msgs[0].Message != "disk full" || msgs[0].AppName != "cleaner" {
		t.Errorf("got %q / %q / %q", msgs[0].SeverityLabel, msgs[0].Message, msgs[0].AppName)
	}
}

// The number that says the format was chosen wrongly, before anything is
// imported on the strength of it.
func TestJSON_CountsLinesThatAreNotJSON(t *testing.T) {
	const content = "2026-03-17 21:42:10 INFO not json at all\nanother plain line\n"
	res, _ := readFormat(t, content, models.ImportFormat{Mode: models.ImportJSON})

	if res.Unmatched != 2 {
		t.Errorf("Unmatched = %d, want 2 — a format that matches nothing must say so", res.Unmatched)
	}
	if res.Imported != 2 {
		t.Errorf("Imported = %d; unmatched lines are kept unless asked otherwise", res.Imported)
	}
}

// --- access logs -------------------------------------------------------------

func TestAccess_ReadsTheTimestampInTheMiddleAndTheStatusAsSeverity(t *testing.T) {
	const content = `10.0.0.4 - - [17/Mar/2026:21:42:10 +0000] "GET /health HTTP/1.1" 500 172 "-" "curl/8.5.0"
10.0.0.5 - alice [17/Mar/2026:21:42:11 +0000] "POST /login HTTP/1.1" 401 88
10.0.0.6 - - [17/Mar/2026:21:42:12 +0000] "GET /index.html HTTP/1.1" 200 5120
`
	res, msgs := readFormat(t, content, models.ImportFormat{Mode: models.ImportAccess})

	if res.Imported != 3 || res.Unmatched != 0 {
		t.Fatalf("Imported = %d, Unmatched = %d, want 3 and 0", res.Imported, res.Unmatched)
	}
	if res.TimeDetected != 3 || res.LevelDetected != 3 {
		t.Fatalf("time=%d level=%d, want 3 and 3", res.TimeDetected, res.LevelDetected)
	}
	want := []string{"Error", "Warning", "Info"}
	for i, w := range want {
		if msgs[i].SeverityLabel != w {
			t.Errorf("status of line %d read as %q, want %q", i, msgs[i].SeverityLabel, w)
		}
	}
	if msgs[0].Hostname != "10.0.0.4" {
		t.Errorf("client = %q", msgs[0].Hostname)
	}
	if got := msgs[0].Timestamp.UTC().Format(time.RFC3339); got != "2026-03-17T21:42:10Z" {
		t.Errorf("timestamp = %s, want the one inside the brackets", got)
	}
	if !strings.Contains(msgs[1].Message, "user=alice") {
		t.Errorf("the authenticated user was dropped: %q", msgs[1].Message)
	}
}

// --- logfmt ------------------------------------------------------------------

func TestLogfmt_ReadsPairsAndKeepsTheRest(t *testing.T) {
	const content = `ts=2026-03-17T21:42:10Z level=debug msg="cache warm" entries=4821 took=38ms` + "\n" +
		`ts=2026-03-17T21:42:11Z level=error msg="connection refused" err="dial tcp: timeout"` + "\n"
	res, msgs := readFormat(t, content, models.ImportFormat{Mode: models.ImportLogfmt})

	if res.LevelDetected != 2 || res.TimeDetected != 2 {
		t.Fatalf("level=%d time=%d, want 2 and 2", res.LevelDetected, res.TimeDetected)
	}
	if msgs[0].SeverityLabel != "Debug" {
		t.Errorf("severity = %q", msgs[0].SeverityLabel)
	}
	if !strings.HasPrefix(msgs[0].Message, "cache warm") {
		t.Errorf("message = %q", msgs[0].Message)
	}
	// A quoted value with spaces in it survives, and the pairs that are not
	// fields are still part of what the line says.
	if !strings.Contains(msgs[0].Message, "entries=4821") || !strings.Contains(msgs[0].Message, "took=38ms") {
		t.Errorf("the other pairs were dropped: %q", msgs[0].Message)
	}
	if !strings.Contains(msgs[1].Message, "dial tcp: timeout") {
		t.Errorf("a quoted value was cut at the space: %q", msgs[1].Message)
	}
}

// --- a custom pattern --------------------------------------------------------

func TestCustom_ReadsNamedGroups(t *testing.T) {
	const content = "E/ActivityManager( 1234): ANR in com.example.app\nI/ActivityManager( 1234): start proc\n"
	res, msgs := readFormat(t, content, models.ImportFormat{
		Mode:    models.ImportCustom,
		Pattern: `^(?P<level>[VDIWEF])/(?P<app>[^(]+)\(\s*\d+\): (?P<msg>.*)$`,
	})

	if res.Imported != 2 || res.LevelDetected != 2 {
		t.Fatalf("Imported = %d, LevelDetected = %d, want 2 and 2", res.Imported, res.LevelDetected)
	}
	if msgs[0].SeverityLabel != "Error" || msgs[0].AppName != "ActivityManager" {
		t.Errorf("got %q / %q", msgs[0].SeverityLabel, msgs[0].AppName)
	}
	if msgs[0].Message != "ANR in com.example.app" {
		t.Errorf("message = %q", msgs[0].Message)
	}
	if msgs[1].SeverityLabel != "Info" {
		t.Errorf("single-letter I read as %q", msgs[1].SeverityLabel)
	}
}

func TestCustom_UsesTheLayoutItIsGiven(t *testing.T) {
	const content = "17/03/2026 21:42:10 | WARN | disk almost full\n"
	res, msgs := readFormat(t, content, models.ImportFormat{
		Mode:       models.ImportCustom,
		Pattern:    `^(?P<time>[\d/]+ [\d:]+) \| (?P<level>\w+) \| (?P<msg>.*)$`,
		TimeLayout: "02/01/2006 15:04:05",
	})

	if res.TimeDetected != 1 {
		t.Fatalf("a day-first timestamp was not read with the layout it was given")
	}
	if got := msgs[0].Timestamp.UTC().Format(time.RFC3339); got != "2026-03-17T21:42:10Z" {
		t.Errorf("timestamp = %s, want 17 March and not 3 May", got)
	}
	if res.LevelDetected != 1 || msgs[0].Message != "disk almost full" {
		t.Errorf("level=%d message=%q", res.LevelDetected, msgs[0].Message)
	}
}

// A pattern is said before the file is opened, so the answer is what is wrong
// with it rather than "0 lines imported".
func TestCustom_SaysWhatIsWrongWithAPattern(t *testing.T) {
	tests := []struct {
		name, pattern, want string
	}{
		{"broken regex", `^(?P<msg>.*`, "does not compile"},
		{"no named groups", `^.*$`, "no named groups"},
		{"a group nobody reads", `^(?P<mesage>.*)$`, "the names are"},
		{"nothing at all", ``, "needs a pattern"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newParser(models.ImportFormat{Mode: models.ImportCustom, Pattern: tt.pattern})
			if err == nil {
				t.Fatalf("pattern %q was accepted", tt.pattern)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Errorf("error %q does not say %q", err, tt.want)
			}
		})
	}
}

// --- continuation lines ------------------------------------------------------

// The reason a declared format is worth having: forty lines of stack trace are
// one Error, not forty Notices that bury it.
func TestJoinContinuations_FoldsAStackTraceIntoItsMessage(t *testing.T) {
	const content = `2026-03-17 21:42:10 ERROR failed to start
java.lang.IllegalStateException: no datasource
	at com.example.App.main(App.java:42)
	at java.base/java.lang.Thread.run(Thread.java:840)
2026-03-17 21:42:11 INFO shutting down
`
	f := models.ImportFormat{Mode: models.ImportAuto, JoinContinuations: true}
	res, msgs := readFormat(t, content, f)

	if res.Imported != 2 {
		t.Fatalf("Imported = %d, want 2 — the stack trace is part of the error above it", res.Imported)
	}
	if res.Joined != 3 {
		t.Errorf("Joined = %d, want 3", res.Joined)
	}
	// A joined line found its place, so it is not an unrecognised one. Counted
	// both ways, a file that was read perfectly would report a handful of
	// unrecognised lines and read as a warning about nothing.
	if res.Unmatched != 0 {
		t.Errorf("Unmatched = %d, want 0: the trace lines were joined, not lost", res.Unmatched)
	}
	if !strings.Contains(msgs[0].Message, "IllegalStateException") ||
		!strings.Contains(msgs[0].Message, "Thread.java:840") {
		t.Errorf("the trace did not land in the message: %q", msgs[0].Message)
	}
	if msgs[0].SeverityLabel != "Error" || msgs[1].SeverityLabel != "Info" {
		t.Errorf("severities = %q / %q", msgs[0].SeverityLabel, msgs[1].SeverityLabel)
	}
	// Without joining, every trace line is its own Notice — which is the state
	// the feature exists to fix, and worth pinning so it cannot come back.
	plain, _ := readFormat(t, content, models.ImportFormat{Mode: models.ImportAuto})
	if plain.Imported != 5 {
		t.Errorf("without joining, Imported = %d, want 5", plain.Imported)
	}
}

// The guard that matters more than the feature: a file where nothing starts a
// record must not collapse into one message.
func TestJoinContinuations_DoesNotSwallowAFileThatStartsNoRecords(t *testing.T) {
	const content = "just some text\nand another line\nand a third\n"
	res, msgs := readFormat(t, content, models.ImportFormat{
		Mode: models.ImportAuto, JoinContinuations: true,
	})

	if res.Imported != 3 || res.Joined != 0 {
		t.Fatalf("Imported = %d, Joined = %d, want 3 and 0", res.Imported, res.Joined)
	}
	if msgs[1].Message != "and another line" {
		t.Errorf("message = %q", msgs[1].Message)
	}
}

func TestSkipUnmatched_DropsAndCountsTheLinesThatDoNotFit(t *testing.T) {
	const content = `# collector archive, rotated nightly
# host: web-1
2026-03-17 21:42:10 INFO started
2026-03-17 21:42:11 WARN slow
`
	res, msgs := readFormat(t, content, models.ImportFormat{
		Mode: models.ImportAuto, SkipUnmatched: true,
	})

	if res.Imported != 2 || len(msgs) != 2 {
		t.Fatalf("Imported = %d, want 2 — the banner is not a message", res.Imported)
	}
	if res.Unmatched != 2 {
		t.Errorf("Unmatched = %d, want 2; dropped lines must still be counted", res.Unmatched)
	}
}

// In a syslog file a line without a priority is the tail of the one before it
// far more often than it is a message of its own.
func TestSyslogMode_AttachesLinesWithoutAPriority(t *testing.T) {
	const content = "<131>1 2026-03-17T21:42:10Z vpn-gw-01 ipsec - - - tunnel down\n  detail: peer unreachable\n"
	res, msgs := readFormat(t, content, models.ImportFormat{
		Mode: models.ImportSyslog, JoinContinuations: true,
	})

	if res.Imported != 1 || res.Joined != 1 {
		t.Fatalf("Imported = %d, Joined = %d, want 1 and 1", res.Imported, res.Joined)
	}
	if !strings.Contains(msgs[0].Message, "peer unreachable") {
		t.Errorf("message = %q", msgs[0].Message)
	}
	if msgs[0].SeverityLabel != "Error" {
		t.Errorf("severity = %q, want the priority's", msgs[0].SeverityLabel)
	}
}

// --- year and zone -----------------------------------------------------------

// A BSD timestamp carries no year, so importing a 2019 archive in 2026 files
// every line seven years late unless the year can be said.
func TestFormat_UsesTheYearItIsGiven(t *testing.T) {
	const content = "Mar 17 21:42:10 web-1 nginx: upstream timed out\n"
	_, msgs := readFormat(t, content, models.ImportFormat{Mode: models.ImportAuto, Year: 2019})

	if y := msgs[0].Timestamp.Year(); y != 2019 {
		t.Errorf("year = %d, want 2019", y)
	}
}

func TestFormat_ReadsAZonelessStampInTheZoneItIsGiven(t *testing.T) {
	if _, err := time.LoadLocation("Asia/Tokyo"); err != nil {
		t.Skip("no zone database on this host; the application embeds one")
	}
	const content = "2026-03-17 21:42:10 INFO started\n"
	_, msgs := readFormat(t, content, models.ImportFormat{
		Mode: models.ImportAuto, Timezone: "Asia/Tokyo",
	})

	// 21:42 in Tokyo is 12:42 UTC. Read as UTC it would still say 21:42.
	if got := msgs[0].Timestamp.UTC().Format("15:04"); got != "12:42" {
		t.Errorf("UTC time = %s, want 12:42 — the zone was ignored", got)
	}
}

func TestFormat_RefusesAZoneItCannotResolve(t *testing.T) {
	_, err := newParser(models.ImportFormat{Mode: models.ImportAuto, Timezone: "Mars/Olympus"})
	if err == nil {
		t.Fatal("an unknown timezone was accepted")
	}
	if !strings.Contains(err.Error(), "Mars/Olympus") {
		t.Errorf("error does not name the zone: %v", err)
	}
}
