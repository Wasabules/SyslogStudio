package importer

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/syslog"
)

// A DECLARED format, as opposed to the detection in plain.go.
//
// Detection is the default and it is right about the files people write most
// often, but it is measurably not enough: a JSON line, an nginx access line and
// a stack-trace line all come back as "nothing recognised", and a file of
// unrecognised lines does not sort by severity — which is the only reason to
// import it.
//
// Declaring the format buys a second thing, less obvious and worth as much:
// knowing what a record STARTS with. A line that does not start a record
// belongs to the one before it, which is how a forty-line Java stack trace
// becomes one Error instead of forty stray Notices.

const maxPatternLen = 1000

// The named groups a custom pattern may use, and the spellings accepted for
// each. Rejecting an unknown name is deliberate: a pattern with (?P<mesage>…)
// in it would otherwise import an entire file with empty messages and no
// indication of why.
var groupAliases = map[string]string{
	"time": "time", "timestamp": "time", "ts": "time", "date": "time",
	"level": "level", "severity": "level", "lvl": "level", "loglevel": "level", "levelname": "level",
	"host": "host", "hostname": "host",
	"app": "app", "appname": "app", "service": "app", "logger": "app", "program": "app", "tag": "app",
	"msg": "msg", "message": "msg", "text": "msg",
}

// The field names tried in order when a JSON mode is not told which to use.
// Between them they cover pino, bunyan, zap, logrus, serilog, python-json-
// logger and the Elastic Common Schema, which is most of what exists.
var (
	jsonTimeKeys  = []string{"time", "timestamp", "ts", "@timestamp", "eventTime", "datetime", "date"}
	jsonLevelKeys = []string{"level", "severity", "lvl", "levelname", "loglevel", "log.level", "levelName"}
	jsonMsgKeys   = []string{"msg", "message", "text", "@message", "event", "short_message"}
	jsonHostKeys  = []string{"host", "hostname", "source_host", "machine", "host.name"}
	jsonAppKeys   = []string{"app", "application", "service", "logger", "name", "component", "ident"}
)

// The Common and Combined log formats, which nginx, Apache and most things
// imitating them write. The timestamp sits in the middle of the line, which is
// exactly why detection cannot see it.
var accessPattern = regexp.MustCompile(
	`^(\S+) \S+ (\S+) \[([^\]]+)\] "([^"]*)" (\d{3}) (\S+)(?: "([^"]*)" "([^"]*)")?`)

const accessTimeLayout = "02/Jan/2006:15:04:05 -0700"

// Single-letter levels, as logcat, glog and several embedded loggers write
// them. Only ever consulted for a field that was DECLARED to be the level —
// in a free-text line a lone "E" is a letter, not a severity.
var letterLevels = map[string]models.Severity{
	"P": models.SevEmergency, "M": models.SevEmergency,
	"A": models.SevAlert,
	"C": models.SevCritical, "F": models.SevCritical,
	"E": models.SevError,
	"W": models.SevWarning,
	"N": models.SevNotice,
	"I": models.SevInformational,
	"D": models.SevDebug, "V": models.SevDebug, "T": models.SevDebug,
}

// compilePattern turns a custom pattern into something usable, or says what is
// wrong with it. Said before the file is opened, so the answer is "this pattern
// has no named groups" rather than "0 lines imported".
func compilePattern(pattern string) (*regexp.Regexp, error) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil, fmt.Errorf("a custom format needs a pattern")
	}
	if len(pattern) > maxPatternLen {
		return nil, fmt.Errorf("pattern is longer than %d characters", maxPatternLen)
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("pattern does not compile: %w", err)
	}
	named := 0
	for _, name := range re.SubexpNames() {
		if name == "" {
			continue
		}
		if _, ok := groupAliases[strings.ToLower(name)]; !ok {
			return nil, fmt.Errorf(
				"pattern has a group named %q; the names are time, level, host, app and msg", name)
		}
		named++
	}
	if named == 0 {
		return nil, fmt.Errorf(
			"pattern has no named groups: add at least one of (?P<time>...), (?P<level>...) or (?P<msg>...)")
	}
	return re, nil
}

// parser reads lines according to one format.
type parser struct {
	format models.ImportFormat
	re     *regexp.Regexp // custom mode
	year   int
	loc    *time.Location
}

// record is one line's reading.
//
// `start` is the one field the rest of the import turns on: it says the line
// began a record, so a following line that did not can be attached to it.
type record struct {
	msg      models.SyslogMessage
	start    bool
	syslog   bool
	hasTime  bool
	hasLevel bool
}

func newParser(f models.ImportFormat) (*parser, error) {
	f.Normalise()
	if err := models.ValidateImportFormat(f); err != nil {
		return nil, err
	}
	loc, err := f.Location()
	if err != nil {
		return nil, err
	}
	p := &parser{format: f, year: f.Year, loc: loc}
	if f.Mode == models.ImportCustom {
		if p.re, err = compilePattern(f.Pattern); err != nil {
			return nil, err
		}
	}
	return p, nil
}

// parse reads one line.
func (p *parser) parse(line, file string) record {
	switch p.format.Mode {
	case models.ImportSyslog:
		return p.parseSyslog(line, file)
	case models.ImportJSON:
		return p.parseJSON(line, file)
	case models.ImportAccess:
		return p.parseAccess(line, file)
	case models.ImportLogfmt:
		return p.parseLogfmt(line, file)
	case models.ImportCustom:
		return p.parseCustom(line, file)
	default:
		return p.parseAuto(line, file)
	}
}

// base gives a message the shape the rest of the application expects — an id,
// the labels, a sane fallback — with the original line kept as the raw text.
// Building one here instead would mean a second place that has to know how a
// SyslogMessage is filled in.
func base(text, line, file string) models.SyslogMessage {
	msg := syslog.Parse([]byte(text), file, "file")
	msg.RawMessage = line
	return msg
}

func (p *parser) applyTime(msg *models.SyslogMessage, raw string, r *record) {
	if t, ok := p.parseStamp(raw); ok {
		msg.Timestamp = t
		r.hasTime = true
	}
}

func (p *parser) applyLevel(msg *models.SyslogMessage, raw string, r *record) {
	if sev, ok := levelFromString(raw); ok {
		msg.Severity = sev
		msg.SeverityLabel = models.SeverityToLabel(sev)
		r.hasLevel = true
	}
}

// --- automatic ---------------------------------------------------------------

func (p *parser) parseAuto(line, file string) record {
	if isSyslogLine(line) {
		return record{msg: syslog.Parse([]byte(line), file, "file"), start: true, syslog: true}
	}

	d := Detect(line, p.year, p.loc)
	msg := base(d.Rest, line, file)
	r := record{msg: msg}
	if d.HasTime {
		r.msg.Timestamp = d.Timestamp
		r.hasTime = true
	}
	if d.HasLevel {
		r.msg.Severity = d.Severity
		r.msg.SeverityLabel = models.SeverityToLabel(d.Severity)
		r.hasLevel = true
	}
	// A line that said something about itself began a record. One that said
	// nothing did not — which is what lets a stack trace attach to the line
	// above it without a file of plain sentences collapsing into one message.
	r.start = r.hasTime || r.hasLevel
	return r
}

func isSyslogLine(line string) bool {
	return strings.HasPrefix(strings.TrimLeft(line, " \t"), "<")
}

// --- syslog ------------------------------------------------------------------

func (p *parser) parseSyslog(line, file string) record {
	msg := syslog.Parse([]byte(line), file, "file")
	if isSyslogLine(line) {
		return record{msg: msg, start: true, syslog: true}
	}
	// No priority: the parser's fallback stands, and the line did not start a
	// record — in a syslog file, a line without a PRI is the tail of the one
	// before it far more often than it is a message of its own.
	msg.RawMessage = line
	return record{msg: msg}
}

// --- JSON --------------------------------------------------------------------

func (p *parser) parseJSON(line, file string) record {
	trimmed := strings.TrimSpace(line)
	if !strings.HasPrefix(trimmed, "{") {
		return record{msg: base(line, line, file)}
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err != nil {
		return record{msg: base(line, line, file)}
	}

	text, _ := pickString(obj, p.format.JSONMessage, jsonMsgKeys)
	if text == "" {
		// A JSON line with no message field is still a record; showing the
		// object beats showing an empty row.
		text = trimmed
	}
	msg := base(text, line, file)
	r := record{msg: msg, start: true}

	if v, ok := pick(obj, p.format.JSONTime, jsonTimeKeys); ok {
		if t, ok := p.parseStampValue(v); ok {
			r.msg.Timestamp = t
			r.hasTime = true
		}
	}
	if v, ok := pick(obj, p.format.JSONLevel, jsonLevelKeys); ok {
		if sev, ok := levelFromValue(v); ok {
			r.msg.Severity = sev
			r.msg.SeverityLabel = models.SeverityToLabel(sev)
			r.hasLevel = true
		}
	}
	if h, ok := pickString(obj, p.format.JSONHost, jsonHostKeys); ok && h != "" {
		r.msg.Hostname = h
	}
	if a, ok := pickString(obj, p.format.JSONApp, jsonAppKeys); ok && a != "" {
		r.msg.AppName = a
	}
	return r
}

// pick reads the configured field, or the first of the usual ones that is
// present. Nothing is invented: an absent field simply leaves its part of the
// message alone.
func pick(obj map[string]any, configured string, candidates []string) (any, bool) {
	if configured != "" {
		v, ok := obj[configured]
		return v, ok
	}
	for _, k := range candidates {
		if v, ok := obj[k]; ok {
			return v, true
		}
	}
	return nil, false
}

func pickString(obj map[string]any, configured string, candidates []string) (string, bool) {
	v, ok := pick(obj, configured, candidates)
	if !ok {
		return "", false
	}
	return valueString(v), true
}

func valueString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	case nil:
		return ""
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return fmt.Sprint(t)
		}
		return string(b)
	}
}

// --- access logs -------------------------------------------------------------

func (p *parser) parseAccess(line, file string) record {
	m := accessPattern.FindStringSubmatch(line)
	if m == nil {
		return record{msg: base(line, line, file)}
	}

	client, user, stamp, request, status, size := m[1], m[2], m[3], m[4], m[5], m[6]
	text := fmt.Sprintf("%s %s %s", request, status, size)
	if user != "-" && user != "" {
		text += " user=" + user
	}
	if len(m) > 8 && m[8] != "" {
		text += fmt.Sprintf(" ua=%q", m[8])
	}

	msg := base(text, line, file)
	msg.Hostname = client
	r := record{msg: msg, start: true}

	if t, err := time.Parse(accessTimeLayout, stamp); err == nil {
		r.msg.Timestamp = t
		r.hasTime = true
	} else if t, ok := p.parseStamp(stamp); ok {
		r.msg.Timestamp = t
		r.hasTime = true
	}

	// An access log has no severity field; the status code is the severity,
	// and it is the reason anyone imports one — 500s are what is being looked
	// for. Counted as inferred, because it is.
	if code, err := strconv.Atoi(status); err == nil {
		sev := models.SevInformational
		switch {
		case code >= 500:
			sev = models.SevError
		case code >= 400:
			sev = models.SevWarning
		}
		r.msg.Severity = sev
		r.msg.SeverityLabel = models.SeverityToLabel(sev)
		r.hasLevel = true
	}
	return r
}

// --- logfmt ------------------------------------------------------------------

func (p *parser) parseLogfmt(line, file string) record {
	pairs := parseLogfmtPairs(line)
	if len(pairs) == 0 {
		return record{msg: base(line, line, file)}
	}

	obj := make(map[string]any, len(pairs))
	var rest []string
	for _, kv := range pairs {
		obj[kv[0]] = kv[1]
	}

	text, _ := pickString(obj, p.format.JSONMessage, jsonMsgKeys)
	// Whatever is not one of the known fields is still information — an error
	// string, a duration, a request id. Kept after the message rather than
	// dropped, since the line is being read for what it says.
	known := map[string]bool{}
	for _, k := range fieldNames(p.format) {
		known[k] = true
	}
	for _, kv := range pairs {
		if !known[kv[0]] {
			rest = append(rest, kv[0]+"="+kv[1])
		}
	}
	if text == "" {
		text = strings.Join(rest, " ")
		rest = nil
	} else if len(rest) > 0 {
		text = text + " " + strings.Join(rest, " ")
	}

	msg := base(text, line, file)
	r := record{msg: msg, start: true}

	if v, ok := pickString(obj, p.format.JSONTime, jsonTimeKeys); ok {
		p.applyTime(&r.msg, v, &r)
	}
	if v, ok := pickString(obj, p.format.JSONLevel, jsonLevelKeys); ok {
		p.applyLevel(&r.msg, v, &r)
	}
	if h, ok := pickString(obj, p.format.JSONHost, jsonHostKeys); ok && h != "" {
		r.msg.Hostname = h
	}
	if a, ok := pickString(obj, p.format.JSONApp, jsonAppKeys); ok && a != "" {
		r.msg.AppName = a
	}
	return r
}

// fieldNames lists the keys that are consumed as fields, so everything else can
// be kept in the message.
func fieldNames(f models.ImportFormat) []string {
	var out []string
	add := func(configured string, candidates []string) {
		if configured != "" {
			out = append(out, configured)
			return
		}
		out = append(out, candidates...)
	}
	add(f.JSONTime, jsonTimeKeys)
	add(f.JSONLevel, jsonLevelKeys)
	add(f.JSONMessage, jsonMsgKeys)
	add(f.JSONHost, jsonHostKeys)
	add(f.JSONApp, jsonAppKeys)
	return out
}

// parseLogfmtPairs reads key=value pairs, honouring quotes so a message with
// spaces in it survives.
func parseLogfmtPairs(line string) [][2]string {
	var out [][2]string
	i := 0
	for i < len(line) {
		for i < len(line) && line[i] == ' ' {
			i++
		}
		start := i
		for i < len(line) && line[i] != '=' && line[i] != ' ' {
			i++
		}
		if i >= len(line) || line[i] != '=' {
			// A bare word is not a pair. Skip it rather than guessing.
			for i < len(line) && line[i] != ' ' {
				i++
			}
			continue
		}
		key := line[start:i]
		i++ // past '='

		var value string
		if i < len(line) && line[i] == '"' {
			i++
			var b strings.Builder
			for i < len(line) && line[i] != '"' {
				if line[i] == '\\' && i+1 < len(line) {
					i++
				}
				b.WriteByte(line[i])
				i++
			}
			i++ // past the closing quote
			value = b.String()
		} else {
			vs := i
			for i < len(line) && line[i] != ' ' {
				i++
			}
			value = line[vs:i]
		}
		if key != "" {
			out = append(out, [2]string{key, value})
		}
	}
	return out
}

// --- a custom pattern --------------------------------------------------------

func (p *parser) parseCustom(line, file string) record {
	m := p.re.FindStringSubmatch(line)
	if m == nil {
		return record{msg: base(line, line, file)}
	}

	fields := map[string]string{}
	for i, name := range p.re.SubexpNames() {
		if name == "" || i >= len(m) {
			continue
		}
		if canonical, ok := groupAliases[strings.ToLower(name)]; ok && m[i] != "" {
			fields[canonical] = m[i]
		}
	}

	text := fields["msg"]
	if text == "" {
		// A pattern that captures a timestamp and a level but no message still
		// has to show something, and the line itself is the honest choice.
		text = line
	}
	msg := base(text, line, file)
	r := record{msg: msg, start: true}

	if v := fields["time"]; v != "" {
		p.applyTime(&r.msg, v, &r)
	}
	if v := fields["level"]; v != "" {
		p.applyLevel(&r.msg, v, &r)
	}
	if v := fields["host"]; v != "" {
		r.msg.Hostname = v
	}
	if v := fields["app"]; v != "" {
		r.msg.AppName = v
	}
	return r
}

// --- shared readings ---------------------------------------------------------

// parseStamp reads a timestamp field: the configured layout if there is one,
// the shapes this package knows otherwise, and epoch numbers, because JSON logs
// write them far more often than they write strings.
func (p *parser) parseStamp(v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}

	if p.format.TimeLayout != "" {
		if t, err := time.ParseInLocation(p.format.TimeLayout, v, p.loc); err == nil {
			return p.fixYear(t), true
		}
		// A layout that does not fit is worth saying, but not worth losing the
		// line over: the known shapes are still tried below.
	}

	parseable := strings.Replace(v, ",", ".", 1)
	for _, layout := range timeLayouts {
		if t, err := time.ParseInLocation(layout, parseable, p.loc); err == nil {
			return p.fixYear(t), true
		}
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t, true
	}
	if n, err := strconv.ParseFloat(v, 64); err == nil {
		return epochToTime(n)
	}
	return time.Time{}, false
}

func (p *parser) parseStampValue(v any) (time.Time, bool) {
	switch t := v.(type) {
	case float64:
		return epochToTime(t)
	case string:
		return p.parseStamp(t)
	default:
		return p.parseStamp(valueString(v))
	}
}

// A BSD-shaped stamp carries no year, and Go defaults it to year 0, which would
// file every line under the first century.
func (p *parser) fixYear(t time.Time) time.Time {
	if t.Year() != 0 {
		return t
	}
	return time.Date(p.year, t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(),
		t.Nanosecond(), p.loc)
}

// epochToTime reads a numeric timestamp. The unit is taken from the magnitude,
// which is the only thing a bare number offers: seconds since 1973 and
// nanoseconds are eleven digits apart.
func epochToTime(n float64) (time.Time, bool) {
	switch {
	case n >= 1e17:
		return time.Unix(0, int64(n)), true
	case n >= 1e14:
		return time.UnixMicro(int64(n)), true
	case n >= 1e11:
		return time.UnixMilli(int64(n)), true
	case n >= 1e8:
		sec, frac := int64(n), n-float64(int64(n))
		return time.Unix(sec, int64(frac*1e9)), true
	default:
		return time.Time{}, false
	}
}

// levelFromString reads a level that was DECLARED to be one, which is why it
// accepts more than the detector does: a word, a single letter, or a number.
func levelFromString(s string) (models.Severity, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	upper := strings.ToUpper(s)
	if sev, ok := severityWords[upper]; ok {
		return sev, true
	}
	if len(upper) == 1 {
		if sev, ok := letterLevels[upper]; ok {
			return sev, true
		}
	}
	if n, err := strconv.ParseFloat(s, 64); err == nil {
		return levelFromNumber(n)
	}
	return 0, false
}

func levelFromValue(v any) (models.Severity, bool) {
	switch t := v.(type) {
	case float64:
		return levelFromNumber(t)
	case string:
		return levelFromString(t)
	default:
		return levelFromString(valueString(v))
	}
}

// levelFromNumber reads a numeric level.
//
// Two scales exist and they do not overlap, so neither has to be configured:
// the syslog severities (0-7) and the 10-60 scale of pino and bunyan. The
// second one is read as pino writes it — 10 trace, 20 debug, 30 info, 40 warn,
// 50 error, 60 fatal. Python's logging module numbers its levels differently on
// the same range (20 is INFO, not debug), but its JSON formatters write
// `levelname` as a word, so the ambiguous case does not arise in practice. A
// file where it does is what the field name and the custom pattern are for.
func levelFromNumber(n float64) (models.Severity, bool) {
	i := int(n)
	if float64(i) != n {
		return 0, false
	}
	if i >= 0 && i <= 7 {
		return models.Severity(i), true
	}
	switch {
	case i >= 60:
		return models.SevCritical, true // pino's fatal
	case i >= 50:
		return models.SevError, true
	case i >= 40:
		return models.SevWarning, true
	case i >= 30:
		return models.SevInformational, true
	case i >= 20:
		return models.SevDebug, true
	case i >= 10:
		return models.SevDebug, true
	}
	return 0, false
}
