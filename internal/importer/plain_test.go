package importer

import (
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

var utc = time.UTC

func TestDetect_Timestamps(t *testing.T) {
	cases := []struct {
		name string
		line string
		want string // RFC3339 of what should be read, "" for "nothing recognised"
		rest string
	}{
		{"RFC 3339", "2026-03-17T21:42:10Z tunnel down", "2026-03-17T21:42:10Z", "tunnel down"},
		{"RFC 3339 with milliseconds", "2026-03-17T21:42:10.250Z tunnel down", "2026-03-17T21:42:10.25Z", "tunnel down"},
		{"space separated", "2026-03-17 21:42:10 tunnel down", "2026-03-17T21:42:10Z", "tunnel down"},
		{"bracketed", "[2026-03-17 21:42:10] tunnel down", "2026-03-17T21:42:10Z", "tunnel down"},
		{"apache", `10.0.0.1 - - [17/Mar/2026:21:42:10 +0000] "GET / HTTP/1.1"`, "", ""},
		{"BSD, no year", "Mar 17 21:42:10 vpn-gw-01 ipsec: down", "2026-03-17T21:42:10Z", "vpn-gw-01 ipsec: down"},
		{"no timestamp at all", "something happened", "", "something happened"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := Detect(c.line, 2026, utc)
			if c.want == "" {
				if got.HasTime {
					t.Fatalf("read a timestamp where there is none: %s", got.Timestamp)
				}
				if c.rest != "" && got.Rest != c.rest {
					t.Errorf("Rest = %q, want %q", got.Rest, c.rest)
				}
				return
			}
			if !got.HasTime {
				t.Fatalf("no timestamp recognised in %q", c.line)
			}
			if got.Timestamp.UTC().Format(time.RFC3339Nano) != c.want {
				t.Errorf("Timestamp = %s, want %s",
					got.Timestamp.UTC().Format(time.RFC3339Nano), c.want)
			}
			if got.Rest != c.rest {
				t.Errorf("Rest = %q, want %q", got.Rest, c.rest)
			}
		})
	}
}

// A date in the middle of a sentence is data, not the moment the line was
// written. Reading it as the line's own time would reorder the file around a
// coincidence.
func TestDetect_IgnoresATimestampThatIsNotAtTheFront(t *testing.T) {
	got := Detect("service restarted at 2026-01-01 00:00:00 by operator", 2026, utc)
	if got.HasTime {
		t.Fatalf("took a date out of the middle of a line: %s", got.Timestamp)
	}
}

func TestDetect_Severities(t *testing.T) {
	cases := map[string]models.Severity{
		"ERROR connection refused":        models.SevError,
		"error connection refused":        models.SevError,
		"[WARN] disk almost full":         models.SevWarning,
		"WARNING: disk almost full":       models.SevWarning,
		"level=debug msg=\"starting\"":    models.SevDebug,
		"FATAL cannot bind":               models.SevCritical,
		"<INFO> ready":                    models.SevInformational,
		"app|TRACE|entering":              models.SevDebug,
		"2026-03-17 21:42:10 ERR timeout": models.SevError,
	}
	for line, want := range cases {
		got := Detect(line, 2026, utc)
		if !got.HasLevel {
			t.Errorf("%q: no severity recognised", line)
			continue
		}
		if got.Severity != want {
			t.Errorf("%q: severity = %s, want %s", line,
				models.SeverityToLabel(got.Severity), models.SeverityToLabel(want))
		}
	}
}

// The boundaries are the whole point. Without them "ERR" matches inside
// "TERRAFORM" and every line of an infrastructure log becomes an error.
func TestDetect_DoesNotFindLevelsInsideWords(t *testing.T) {
	for _, line := range []string{
		"terraform apply complete",
		"referral accepted",
		"INFORMATIONAL_EVENT_RAISED",
		"deleted /var/log/warnings.old",
		"user alerted the operator",
	} {
		if got := Detect(line, 2026, utc); got.HasLevel {
			t.Errorf("%q: found %s inside a word", line, models.SeverityToLabel(got.Severity))
		}
	}
}

// The severity word stays in the message. Removing it would make the imported
// line disagree with the file it came from.
func TestDetect_KeepsTheSeverityWordInTheText(t *testing.T) {
	got := Detect("2026-03-17 21:42:10 ERROR connection refused", 2026, utc)
	if got.Rest != "ERROR connection refused" {
		t.Fatalf("Rest = %q, want the severity word left in place", got.Rest)
	}
}

func TestDetect_SaysWhenItKnowsNothing(t *testing.T) {
	got := Detect("a line with neither", 2026, utc)
	if got.HasTime || got.HasLevel {
		t.Fatalf("claimed to recognise something: time=%v level=%v", got.HasTime, got.HasLevel)
	}
	if got.Rest != "a line with neither" {
		t.Errorf("Rest = %q, want the line unchanged", got.Rest)
	}
}
