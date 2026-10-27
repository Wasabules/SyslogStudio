package search

import (
	"strings"
	"time"
	"unicode/utf8"

	"SyslogStudio/internal/models"
)

// Filter is a whole FilterCriteria compiled once: the search plan, and every
// other criterion with the one meaning it has in the live view, the history
// and an export alike. The receiver's buffer applies it with Match, the log
// store turns its parts into SQL, and the window follows the same rules in
// lib/search.ts, held to them by testdata/filters.json.
type Filter struct {
	Plan Plan

	Severities map[int]bool
	Facilities map[int]bool

	// Hostname and AppName are text boxes: a field passes when it contains
	// what was typed, case and Latin accents aside.
	Hostname, AppName Field
	// SourceIP is the address box: one address exactly, a CIDR, a pattern
	// with "*", or text the address contains (Address).
	SourceIP Address

	// From and To bound the time range: From included, To excluded. Zero
	// means unbounded.
	From, To time.Time

	// GroupField and GroupKey pick one group, exactly as grouping made it.
	GroupField string
	GroupKey   string
}

// The fields a group can be made of, as FilterCriteria.GroupField names them.
const (
	GroupSeverity = "severity"
	GroupHostname = "hostname"
	GroupAppName  = "appName"
	GroupSourceIP = "sourceIP"
)

// CompileFilter compiles criteria.
func CompileFilter(c models.FilterCriteria) Filter {
	f := Filter{
		Plan:       Compile(c.Search, c.SearchMode),
		Hostname:   NewField(c.Hostname),
		AppName:    NewField(c.AppName),
		SourceIP:   CompileAddress(c.SourceIP, true),
		GroupField: c.GroupField,
		GroupKey:   c.GroupKey,
	}
	if len(c.Severities) > 0 {
		f.Severities = make(map[int]bool, len(c.Severities))
		for _, s := range c.Severities {
			f.Severities[s] = true
		}
	}
	if len(c.Facilities) > 0 {
		f.Facilities = make(map[int]bool, len(c.Facilities))
		for _, x := range c.Facilities {
			f.Facilities[x] = true
		}
	}
	f.From, _ = startOf(c.DateFrom)
	if t, span := startOf(c.DateTo); !t.IsZero() {
		f.To = t.Add(span)
	}
	return f
}

// startOf reads a bound of the time range, and how much it covers. The window
// sends instants (RFC 3339, an end already exclusive); a bare date or a time
// without a zone — a filter saved before it did — is the machine's local time,
// and stands for its whole day or minute.
func startOf(s string) (time.Time, time.Duration) {
	if s == "" {
		return time.Time{}, 0
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, 0
	}
	for _, layout := range []struct {
		layout string
		span   time.Duration
	}{
		{"2006-01-02T15:04:05", time.Second},
		{"2006-01-02T15:04", time.Minute},
		{"2006-01-02", 24 * time.Hour},
	} {
		if t, err := time.ParseInLocation(layout.layout, s, time.Local); err == nil {
			return t, layout.span
		}
	}
	return time.Time{}, 0
}

// Match reports whether a message passes every criterion.
func (f *Filter) Match(msg models.SyslogMessage) bool {
	if f.Severities != nil && !f.Severities[int(msg.Severity)] {
		return false
	}
	if f.Facilities != nil && !f.Facilities[int(msg.Facility)] {
		return false
	}
	if !f.Hostname.Match(msg.Hostname) || !f.AppName.Match(msg.AppName) || !f.SourceIP.Match(msg.SourceIP) {
		return false
	}
	if !f.From.IsZero() && msg.Timestamp.Before(f.From) {
		return false
	}
	if !f.To.IsZero() && !msg.Timestamp.Before(f.To) {
		return false
	}
	if f.GroupField != "" && GroupKey(msg, f.GroupField) != f.GroupKey {
		return false
	}
	return f.Plan.Match(msg.Message, msg.RawMessage)
}

// GroupKey is what a message is grouped by: the field's value as it is, with
// no folding, so that a group holds exactly the messages it counts.
func GroupKey(msg models.SyslogMessage, field string) string {
	switch field {
	case GroupSeverity:
		return msg.SeverityLabel
	case GroupHostname:
		return msg.Hostname
	case GroupAppName:
		return msg.AppName
	case GroupSourceIP:
		return msg.SourceIP
	}
	return ""
}

// Field is a text field box: hostname, application.
type Field struct {
	// Needle is what was typed, folded.
	Needle string
}

// NewField compiles what was typed in a field box. It is used as typed,
// spaces included, as everywhere else.
func NewField(typed string) Field { return Field{Needle: Fold(typed)} }

// Match reports whether value contains the needle, both folded.
func (f Field) Match(value string) bool {
	return f.Needle == "" || strings.Contains(Fold(value), f.Needle)
}

// Fold is text as the field boxes compare it: lowercase, and without the
// accents Words takes off Latin letters, but otherwise as it is — punctuation
// and spaces included, since "web-01" is typed with its hyphen.
func Fold(text string) string {
	for i := 0; i < len(text); i++ {
		if text[i] >= utf8.RuneSelf {
			return foldAll(text)
		}
	}
	return strings.ToLower(text)
}

func foldAll(text string) string {
	var b strings.Builder
	b.Grow(len(text))
	for _, r := range text {
		if !isAccent(r) {
			b.WriteRune(fold(r))
		}
	}
	return b.String()
}
