// Package importer reads log files from disk and turns their lines into
// messages the rest of the application already knows how to show.
//
// Two shapes arrive in practice and they need very different handling.
//
// A captured SYSLOG file — lines beginning with a <PRI> — is already the thing
// this application parses off the wire, so those lines go through the very same
// parser. Nothing is guessed, and severity, facility, host and timestamp are
// whatever the sender said.
//
// A PLAIN application log is not that. It has no PRI, and syslog.Parse
// deliberately makes such a line a Notice stamped with the moment it was read,
// which is the right answer for a stray line off the network and the wrong one
// for a file: the reporter of #46 asked to "sort them according the severity",
// and a file of ten thousand identical Notices sorts into one heap.
//
// So this package reads what a plain line is willing to say: a leading
// timestamp in one of the shapes people actually write, and a severity word
// standing on its own. Both are INFERENCE, and the package is built so the
// caller can show what was inferred before anything is imported — a guess the
// user can see and reject is a feature; a guess presented as fact is not.
package importer

import (
	"regexp"
	"strings"
	"time"

	"SyslogStudio/internal/models"
)

// severityWords maps the words that appear in real logs to syslog severities.
//
// The spellings are the ones logging libraries actually emit, which is why
// several map to the same level: "WARN" and "WARNING" are the same thing, and
// arguing about it would only make the table miss lines.
var severityWords = map[string]models.Severity{
	"EMERG": models.SevEmergency, "EMERGENCY": models.SevEmergency, "PANIC": models.SevEmergency,
	"ALERT": models.SevAlert,
	"CRIT":  models.SevCritical, "CRITICAL": models.SevCritical, "FATAL": models.SevCritical,
	"ERR": models.SevError, "ERROR": models.SevError, "SEVERE": models.SevError,
	"WARN": models.SevWarning, "WARNING": models.SevWarning,
	"NOTICE": models.SevNotice,
	"INFO":   models.SevInformational, "INFORMATION": models.SevInformational,
	"DEBUG": models.SevDebug, "TRACE": models.SevDebug, "FINE": models.SevDebug,

	// The three-letter spellings Serilog, NLog and several Go loggers write.
	// "ERR" is above; the rest are here. Each still has to stand on its own to
	// match, so a word ending in "inf" or "dbg" is not a level.
	"FTL": models.SevCritical,
	"WRN": models.SevWarning,
	"INF": models.SevInformational,
	"DBG": models.SevDebug, "VRB": models.SevDebug,
	// java.util.logging, whose FINER and FINEST sit below FINE.
	"FINER": models.SevDebug, "FINEST": models.SevDebug,
}

// severityPattern finds a severity word standing on its own.
//
// The boundaries matter more than the list does. Without them "INFO" matches
// inside "INFORMATIONAL_EVENT" and, worse, "ERR" matches inside "ERROR" — and
// also inside "TERRAFORM", "REFERRAL" and every other word with those three
// letters in the middle. A word that is part of a longer word is not a level.
var severityPattern = regexp.MustCompile(
	`(?i)(?:^|[\s\[\(<|:=,/])(EMERG(?:ENCY)?|PANIC|ALERT|CRIT(?:ICAL)?|FATAL|FTL|ERR(?:OR)?|SEVERE|` +
		`WARN(?:ING)?|WRN|NOTICE|INFO(?:RMATION)?|INF|DEBUG|DBG|TRACE|VRB|FINEST|FINER|FINE)` +
		`(?:$|[\s\]\)>|:=,/\"])`)

// timeToken matches the timestamp shapes people actually write, anchored to the
// start of the line.
//
// Matching the TOKEN first and parsing it afterwards, rather than slicing a
// fixed number of characters per layout: a layout's length says nothing about
// the text it matches once fractions and zones are optional, and slicing by it
// read "2026-03-17T21:42:10Z" as a zoneless stamp and left a stray "Z" at the
// front of the message.
var timeToken = regexp.MustCompile(
	`^(?:` +
		// ISO 8601 / RFC 3339, with or without a fraction and a zone.
		`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?: ?(?:Z|[+-]\d{2}:?\d{2}))?` +
		`|` +
		// Slashes instead of dashes: Go's standard logger, and nginx's error
		// log, which between them account for a great many files.
		`\d{4}/\d{2}/\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?` +
		`|` +
		// Day and month only, as Android and several embedded loggers write.
		// The year comes from the format panel.
		`\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:[.,]\d+)?` +
		`|` +
		// Apache and nginx access logs.
		`\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}(?: [+-]\d{4})?` +
		`|` +
		// RFC 3164, the BSD shape: no year, day space-padded.
		`[A-Za-z]{3} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}` +
		`)`)

// timeLayouts are tried against a token that already looks like a timestamp.
var timeLayouts = []string{
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02T15:04:05.999999999Z0700",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05Z0700",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999 -07:00",
	"2006-01-02 15:04:05.999999999 -0700",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999Z0700",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05 -07:00",
	"2006-01-02 15:04:05",
	"02/Jan/2006:15:04:05 -0700",
	"02/Jan/2006:15:04:05",
	"Jan _2 15:04:05",
	"Jan 2 15:04:05",
	// Go's standard logger and nginx.
	"2006/01/02 15:04:05.999999999",
	"2006/01/02 15:04:05",
	"2006/01/02T15:04:05",
	// Apache's error log, where the year comes last.
	"Mon Jan _2 15:04:05.999999999 2006",
	"Mon Jan 2 15:04:05 2006",
	// Android's logcat and Kubernetes' klog, neither of which writes a year.
	"01-02 15:04:05.999999999",
	"0102 15:04:05.999999999",
}

// syslogBody matches what follows the timestamp in an RFC 3164 line: a
// hostname, then a tag that ends in a colon.
//
// This is the shape rsyslog writes to disk by default, and the one an operator
// is most likely to have in a file — the priority only exists on the wire, so a
// captured file has a timestamp, a host and a tag, and nothing that announces
// itself as syslog. Read as free text (#50), the host and the tag stay inside
// the message and the Hostname and App columns are empty, which is exactly what
// makes such a file useless to filter.
//
// The tag requirement is what keeps this from firing on an ordinary
// application log: "worker pool started with 16 threads" has no
// "something:" token in second position.
var syslogBody = regexp.MustCompile(
	`^([A-Za-z0-9][A-Za-z0-9._:-]{0,253})[ \t]+([^\s:\[]{1,48}(?:\[[0-9]{1,10}\])?:)(?:[ \t]|$)`)

// splitBSDBody reads "HOST TAG[PID]: MSG" out of what follows a timestamp.
//
// The only judgement call is the first token. A level word is never a hostname,
// and a line like "21:42:10 WARN queue: depth 812" would otherwise be filed
// under a host called WARN — so the severity vocabulary is excluded outright.
// Everything else the regular expression settles.
func splitBSDBody(rest string) (host, body string, ok bool) {
	m := syslogBody.FindStringSubmatch(rest)
	if m == nil {
		return "", rest, false
	}
	if _, isLevel := severityWords[strings.ToUpper(m[1])]; isLevel {
		return "", rest, false
	}
	// The body starts at the tag, which ExtractTag then takes off — one
	// definition of what a tag is, shared with the wire parser.
	return m[1], strings.TrimLeft(rest[len(m[1]):], " \t"), true
}

// Detection is what a plain line was willing to say about itself.
type Detection struct {
	Timestamp time.Time
	HasTime   bool
	Severity  models.Severity
	HasLevel  bool
	// Host is the hostname an RFC 3164 body carries in front of its tag, when
	// the line turned out to have that shape.
	Host    string
	HasHost bool
	// Rest is the line with a recognised leading timestamp removed, which is
	// what belongs in the message column. The severity word is left in place:
	// it is part of what the line says, and deleting it would make the import
	// disagree with the file.
	Rest string
}

// detectTime reads a timestamp off the front of a line.
//
// Only the front. A date in the middle of a sentence is data, not the moment
// the line was written, and treating "restarted at 2026-01-01 00:00:00" as the
// line's own time would reorder the file around a coincidence.
func detectTime(line string, year int, loc *time.Location) (time.Time, string, bool) {
	trimmed := strings.TrimLeft(line, " 	")

	// Ruby's Logger, and Rails with it, writes the severity letter and a comma
	// before the bracket: "I, [2026-03-17T21:42:10.123456 #1234]".
	if len(trimmed) > 3 && trimmed[1] == ',' && trimmed[2] == ' ' &&
		trimmed[0] >= 'A' && trimmed[0] <= 'Z' {
		trimmed = trimmed[3:]
	}

	// Many formats bracket the stamp: [2026-03-17 21:42:10].
	bracketed := strings.HasPrefix(trimmed, "[")
	if bracketed {
		trimmed = trimmed[1:]
	}

	token := timeToken.FindString(trimmed)
	if token == "" {
		return time.Time{}, line, false
	}

	// A comma is a decimal separator in several European-formatted logs; Go
	// only parses a dot.
	parseable := strings.Replace(token, ",", ".", 1)

	for _, layout := range timeLayouts {
		t, err := time.ParseInLocation(layout, parseable, loc)
		if err != nil {
			continue
		}
		// A BSD-shaped stamp carries no year; Go defaults it to year 0, which
		// would file every line under the first century.
		if t.Year() == 0 {
			t = time.Date(year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(),
				t.Nanosecond(), loc)
		}
		rest := strings.TrimSpace(trimmed[len(token):])
		if bracketed {
			// Close the bracket the stamp opened, along with whatever else was
			// inside it: Ruby writes "[<time> #1234]", and leaving "#1234]" at
			// the front of the message is something the reader has to step
			// over on every line.
			if i := strings.IndexByte(rest, ']'); i >= 0 && i <= 16 {
				rest = strings.TrimSpace(rest[i+1:])
			}
		}
		rest = strings.TrimSpace(strings.TrimLeft(rest, "-–:"))
		return t, rest, true
	}
	return time.Time{}, line, false
}

// detectSeverity finds a level word standing on its own.
func detectSeverity(line string) (models.Severity, bool) {
	m := severityPattern.FindStringSubmatch(line)
	if m == nil {
		return 0, false
	}
	if sev, ok := severityWords[strings.ToUpper(m[1])]; ok {
		return sev, true
	}
	return 0, false
}

// Detect reads what a plain line is willing to say.
//
// `year` supplies the one a BSD-shaped stamp omits, and `loc` the zone a
// stamp without one is read in — the same two questions the wire parser has to
// answer, asked here because a file cannot answer them either.
func Detect(line string, year int, loc *time.Location) Detection {
	d := Detection{Rest: strings.TrimSpace(line)}
	if loc == nil {
		loc = time.Local
	}

	if t, rest, ok := detectTime(line, year, loc); ok {
		d.Timestamp, d.Rest, d.HasTime = t, rest, true

		// Only after a timestamp. "host tag: message" with nothing in front of
		// it is far more often a sentence with a colon in it than a syslog
		// line, and the cost of being wrong is a message filed under an
		// invented host.
		if host, body, ok := splitBSDBody(d.Rest); ok {
			d.Host, d.Rest, d.HasHost = host, body, true
		}
	}
	if sev, ok := detectSeverity(d.Rest); ok {
		d.Severity, d.HasLevel = sev, true
	}
	return d
}
