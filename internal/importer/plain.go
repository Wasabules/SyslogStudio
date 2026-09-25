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
}

// severityPattern finds a severity word standing on its own.
//
// The boundaries matter more than the list does. Without them "INFO" matches
// inside "INFORMATIONAL_EVENT" and, worse, "ERR" matches inside "ERROR" — and
// also inside "TERRAFORM", "REFERRAL" and every other word with those three
// letters in the middle. A word that is part of a longer word is not a level.
var severityPattern = regexp.MustCompile(
	`(?i)(?:^|[\s\[\(<|:=,/])(EMERG(?:ENCY)?|PANIC|ALERT|CRIT(?:ICAL)?|FATAL|ERR(?:OR)?|SEVERE|` +
		`WARN(?:ING)?|NOTICE|INFO(?:RMATION)?|DEBUG|TRACE|FINE)(?:$|[\s\]\)>|:=,/\"])`)

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
		`\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?` +
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
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02T15:04:05.999999999",
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999 -07:00",
	"2006-01-02 15:04:05.999999999Z07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05Z07:00",
	"2006-01-02 15:04:05 -07:00",
	"2006-01-02 15:04:05",
	"02/Jan/2006:15:04:05 -0700",
	"02/Jan/2006:15:04:05",
	"Jan _2 15:04:05",
	"Jan 2 15:04:05",
}

// Detection is what a plain line was willing to say about itself.
type Detection struct {
	Timestamp time.Time
	HasTime   bool
	Severity  models.Severity
	HasLevel  bool
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
			rest = strings.TrimSpace(strings.TrimPrefix(rest, "]"))
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
	}
	if sev, ok := detectSeverity(d.Rest); ok {
		d.Severity, d.HasLevel = sev, true
	}
	return d
}
