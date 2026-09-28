package importer

import (
	"regexp"
	"strconv"
	"strings"

	"SyslogStudio/internal/models"
)

// Line shapes specific enough to recognise on sight.
//
// Automatic detection reads a timestamp at the front of a line and a severity
// word standing on its own, which covers a great many files and nothing else.
// The formats below defeat it in ways that are not fixable by a wider
// timestamp list: the level is a single letter glued to the date (klog), or
// three integers sit between the timestamp and the level (logcat), or the
// whole header is bracketed with the year at the end (Apache).
//
// Each one is matched by an anchored expression that could not plausibly fit
// anything else, and each is a format someone genuinely has on disk. A shape
// that needed a loose pattern to catch it would not be here: a wrong hostname
// or an invented severity is worse than an unparsed line, because the line
// still shows its text while the field quietly lies.

// The names a line's recognised shape can carry. They are counted per file so
// the interface can say what a file IS — a reader who opens an Apache access
// log wants to be told it is one, not merely to have it parsed correctly
// behind their back.
const (
	ShapeSyslog = "syslog" // a priority, parsed as it would be off the wire
	ShapeBSD    = "bsd"    // RFC 3164 with no priority, as rsyslog writes files
	ShapeJSON   = "json"
	ShapeAccess = "access"
	ShapeLogfmt = "logfmt"
	ShapeKlog   = "klog"
	ShapeLogcat = "logcat"
	ShapeApache = "apache" // the error log, not the access log
	ShapeEpoch  = "epoch"
	ShapeCustom = "custom"
	ShapePlain  = "plain" // a timestamp or a level read out of free text
	ShapeNone   = "none"  // nothing recognised
)

// ModeForShape is the declared format that reads a shape best, for the shapes
// that have one. A klog or a logcat line has no mode of its own: automatic
// detection is where it is read, so there is nothing to switch to.
func ModeForShape(shape string) models.ImportMode {
	switch shape {
	case ShapeSyslog, ShapeBSD:
		return models.ImportSyslog
	case ShapeJSON:
		return models.ImportJSON
	case ShapeAccess:
		return models.ImportAccess
	case ShapeLogfmt:
		return models.ImportLogfmt
	}
	return ""
}

// klog, which every Kubernetes component writes:
//
//	I0317 21:42:10.123456    1234 controller.go:212] Starting workers
//
// The severity is the leading letter, the date carries no year, and the
// source location stands where an application name would.
var klogShape = regexp.MustCompile(
	`^([IWEFD])(\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(\d+)\s+([\w.-]+\.go):(\d+)\]\s?(.*)$`)

// Android's logcat in its threadtime form, which is what `adb logcat` writes
// to a file:
//
//	03-17 21:42:10.123  1234  5678 E ActivityManager: ANR in com.example
var logcatShape = regexp.MustCompile(
	`^(\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3})\s+(\d+)\s+(\d+)\s+([VDIWEFA])\s+([^:]{1,48}):\s?(.*)$`)

// Android's other logcat form, which `adb logcat` writes by default and which
// carries no timestamp at all:
//
//	E/ActivityManager( 1234): ANR in com.example.app
//
// The severity is the leading letter, and the shape — letter, slash, tag, a
// parenthesised pid, colon — is specific enough that nothing else falls in it.
var logcatBriefShape = regexp.MustCompile(
	`^([VDIWEFA])/([^(/]{1,40})\(\s*(\d+)\):\s?(.*)$`)

// Apache's error log, where the header is bracketed and the year comes last:
//
//	[Mon Mar 17 21:42:10.123456 2026] [core:error] [pid 1234] AH00037: ...
var apacheErrorShape = regexp.MustCompile(
	`^\[([A-Z][a-z]{2} [A-Z][a-z]{2} [ \d]?\d \d{2}:\d{2}:\d{2}(?:\.\d+)? \d{4})\]\s*(.*)$`)

// The pid Apache puts in its own bracket, worth keeping because it is how two
// interleaved workers are told apart.
var apachePID = regexp.MustCompile(`^\[pid (\d+)(?::tid \d+)?\]\s*`)

// Squid and several proxies write the epoch, to the millisecond, and nothing
// else a reader would recognise as a date:
//
//	1774388530.123    123 198.51.100.7 TCP_MISS/200 4021 GET http://...
//
// Ten digits and a fraction, anchored, is specific enough; a bare number that
// long at the front of a line is not something else.
var epochShape = regexp.MustCompile(`^(\d{10}\.\d{3})\s+(.*)$`)

// Single letters are read ONLY where a format says the letter is the level.
// In free text a lone "E" is a letter, which is why the detector never uses
// this table and these shapes always do.
var letterSeverity = map[string]models.Severity{
	"A": models.SevCritical, // logcat's Assert
	"F": models.SevCritical,
	"E": models.SevError,
	"W": models.SevWarning,
	"I": models.SevInformational,
	"D": models.SevDebug,
	"V": models.SevDebug,
}

// parseShape tries the shapes that are recognisable on sight.
func (p *parser) parseShape(line, file string) (record, bool) {
	if m := klogShape.FindStringSubmatch(line); m != nil {
		return p.buildKlog(m, line, file), true
	}
	if m := logcatShape.FindStringSubmatch(line); m != nil {
		return p.buildLogcat(m, line, file), true
	}
	if m := logcatBriefShape.FindStringSubmatch(line); m != nil {
		return p.buildLogcatBrief(m, line, file), true
	}
	if m := apacheErrorShape.FindStringSubmatch(line); m != nil {
		return p.buildApacheError(m, line, file), true
	}
	if m := epochShape.FindStringSubmatch(line); m != nil {
		return p.buildEpoch(m, line, file), true
	}
	return record{}, false
}

func (p *parser) withLevel(r *record, token string) {
	if sev, ok := letterSeverity[strings.ToUpper(token)]; ok {
		r.msg.Severity = sev
		r.msg.SeverityLabel = models.SeverityToLabel(sev)
		r.hasLevel = true
	}
}

func (p *parser) withTime(r *record, token string) {
	if t, ok := p.parseStamp(token); ok {
		r.msg.Timestamp = t
		r.hasTime = true
	}
}

func (p *parser) buildKlog(m []string, line, file string) record {
	r := record{msg: base(m[6], line, file), start: true, shape: ShapeKlog}
	p.withLevel(&r, m[1])
	p.withTime(&r, m[2])
	// The source file is what a klog reader filters on — "controller.go" is
	// the component. The thread id goes where a process id would, which is the
	// nearest true thing to say about it.
	r.msg.AppName = m[4]
	r.msg.ProcID = m[3]
	r.hasHost = true
	return r
}

func (p *parser) buildLogcat(m []string, line, file string) record {
	r := record{msg: base(m[6], line, file), start: true, shape: ShapeLogcat}
	p.withTime(&r, m[1])
	p.withLevel(&r, m[4])
	r.msg.AppName = strings.TrimSpace(m[5])
	r.msg.ProcID = m[2]
	r.hasHost = true
	return r
}

func (p *parser) buildLogcatBrief(m []string, line, file string) record {
	r := record{msg: base(m[4], line, file), start: true, shape: ShapeLogcat}
	p.withLevel(&r, m[1])
	r.msg.AppName = strings.TrimSpace(m[2])
	r.msg.ProcID = m[3]
	r.hasHost = true
	return r
}

func (p *parser) buildApacheError(m []string, line, file string) record {
	header := m[2]

	// "[core:error]" carries the level, colon and all, which the severity
	// detector already reads. It is taken off afterwards so the message is the
	// message.
	rest := stripModule(header)
	var pid string
	if pm := apachePID.FindStringSubmatch(rest); pm != nil {
		pid = pm[1]
		rest = strings.TrimSpace(apachePID.ReplaceAllString(rest, ""))
	}

	r := record{msg: base(rest, line, file), start: true, shape: ShapeApache}
	p.withTime(&r, m[1])
	if sev, ok := detectSeverity(header); ok {
		r.msg.Severity = sev
		r.msg.SeverityLabel = models.SeverityToLabel(sev)
		r.hasLevel = true
	}
	if pid != "" {
		r.msg.ProcID = pid
		r.hasHost = true
	}
	return r
}

// stripModule takes off Apache's "[module:level]" bracket once its level has
// been read, so the message is the message.
var moduleBracket = regexp.MustCompile(`^\[[a-z_0-9]+:[a-z]+\]\s*`)

func stripModule(s string) string {
	return moduleBracket.ReplaceAllString(s, "")
}

func (p *parser) buildEpoch(m []string, line, file string) record {
	r := record{msg: base(m[2], line, file), start: true, shape: ShapeEpoch}
	if secs, err := strconv.ParseFloat(m[1], 64); err == nil {
		if t, ok := epochToTime(secs); ok {
			r.msg.Timestamp = t
			r.hasTime = true
		}
	}
	// Whatever the line says about severity, it says in words, and the
	// detector reads those the same way it does anywhere else.
	if sev, ok := detectSeverity(m[2]); ok {
		r.msg.Severity = sev
		r.msg.SeverityLabel = models.SeverityToLabel(sev)
		r.hasLevel = true
	}
	return r
}

// looksLikeJSON and looksLikeLogfmt decide whether automatic detection should
// hand a line to a parser that was written for it.
//
// Both are deliberately strict about the START of the line. A line that begins
// with a timestamp has already said what it is, and handing it to the logfmt
// reader because it happens to contain "err=" somewhere would throw that
// timestamp away.
func looksLikeJSON(line string) bool {
	t := strings.TrimSpace(line)
	return strings.HasPrefix(t, "{") && strings.HasSuffix(t, "}")
}

func looksLikeLogfmt(line string) bool {
	first, _, ok := strings.Cut(strings.TrimSpace(line), " ")
	if !ok && strings.TrimSpace(line) != "" {
		first = strings.TrimSpace(line)
	}
	key, _, ok := strings.Cut(first, "=")
	if !ok || key == "" {
		return false
	}
	// A known field in first position: ts=, time=, level=, msg=. Without this
	// any line starting with "x=1" would be read as logfmt.
	for _, known := range [][]string{jsonTimeKeys, jsonLevelKeys, jsonMsgKeys} {
		for _, k := range known {
			if strings.EqualFold(key, k) {
				return true
			}
		}
	}
	return false
}
