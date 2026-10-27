package importer

import (
	"regexp"
	"strings"
	"time"

	"SyslogStudio/internal/models"
	"SyslogStudio/internal/syslog"
)

// Reading what arrives on the wire.
//
// A great deal of what devices send as syslog is not quite the RFCs: rsyslog
// forwards with an RFC 3339 timestamp and no version, a FortiGate sends
// key=value after its priority, Cisco IOS puts a sequence number and a starred
// timestamp in front, applications log JSON through a syslog driver, and some
// devices send no priority at all. The wire parser reads all of that as text,
// and filed "2026-10-27T09" as the application of every rsyslog message it
// was ever relayed.
//
// The readings this package already does for files are exactly the ones that
// text needs. So a message whose header is the RFCs' is left as the wire
// parser read it, and one whose header is not is read again here — with the
// same JSON, key=value, timestamp and shape readings a file line gets, so the
// wire and a file agree on what a line says.
//
// What the sender declared in its priority stands: a severity read again
// replaces it only when the message declares one in a field of its own (a
// JSON or key=value "level"), never because a level word turned up in the
// text. With no priority at all there is nothing to stand, and a level word at
// the very front of the message is taken.

// WireReader reads messages as they arrive. It is safe for concurrent use.
type WireReader struct {
	p *parser
}

// NewWireReader makes a reader that reads what it is not told about the way
// automatic detection reads a file, in this machine's zone.
func NewWireReader() *WireReader {
	p, _ := newParser(models.ImportFormat{Mode: models.ImportAuto})
	return &WireReader{p: p}
}

// Read reads one message received from sourceIP over protocol.
func (w *WireReader) Read(raw []byte, sourceIP, protocol string) models.SyslogMessage {
	msg, rd := syslog.Read(raw, sourceIP, protocol)
	w.p.reread(&msg, rd)
	return msg
}

// Reread is Read for a message syslog.Read has read already.
func (w *WireReader) Reread(msg *models.SyslogMessage, rd syslog.Reading) {
	w.p.reread(msg, rd)
}

// FormatReader reads a received message again as a declared format says: what
// a source rule (internal/sources) gives for one device. It is safe for
// concurrent use.
type FormatReader struct {
	p *parser
}

// NewFormatReader makes a reader for f, or says what is wrong with it. What
// only means something for a file — joining lines, skipping those that do not
// match — does not apply to a message.
func NewFormatReader(f models.ImportFormat) (*FormatReader, error) {
	f.JoinContinuations, f.SkipUnmatched = false, false
	p, err := newParser(f)
	if err != nil {
		return nil, err
	}
	return &FormatReader{p: p}, nil
}

// Location is the zone a stamp that carries none is read in.
func (r *FormatReader) Location() *time.Location {
	return r.p.loc
}

// Text is what the format reads in a message: what follows the priority when
// the header is not the RFCs', and the message text when it is — the host,
// the application and the time are then read already.
func Text(msg models.SyslogMessage, rd syslog.Reading) string {
	if rd.Standard {
		return msg.Message
	}
	return rd.Body
}

// Reread reads msg again from what Text gives, and reports whether it fitted
// the format. A field the format does not give is left as it was read; one
// it gives replaces it. Automatic detection reads only a header that is not
// the RFCs', in this reader's zone.
func (r *FormatReader) Reread(msg *models.SyslogMessage, rd syslog.Reading) bool {
	text := Text(*msg, rd)
	if strings.TrimSpace(text) == "" {
		return false
	}
	var rec record
	var declared bool
	switch r.p.format.Mode {
	case models.ImportAuto, models.ImportSyslog:
		if rd.Standard {
			return false
		}
		rec, declared = r.p.readBody(text, msg.ReceivedAt)
	default:
		rec = r.p.parse(text, "")
		if !rec.start {
			return false
		}
		declared = rec.shape != ShapePlain && rec.shape != ShapeBSD && rec.shape != ShapeNone
	}
	if rec.hasTime {
		msg.Timestamp = rec.msg.Timestamp
	}
	if rec.msg.Hostname != "" {
		msg.Hostname = rec.msg.Hostname
	}
	if rec.msg.AppName != "" {
		msg.AppName = rec.msg.AppName
		msg.ProcID = rec.msg.ProcID
	}
	msg.Message = rec.msg.Message
	if rec.hasLevel && (declared || !rd.HasPRI) {
		msg.Severity = rec.msg.Severity
		msg.SeverityLabel = rec.msg.SeverityLabel
	}
	return true
}

// FindLevel finds a level word standing on its own anywhere in text: for a
// device that says its level in words and puts the same priority on all.
func FindLevel(text string) (models.Severity, bool) {
	return detectSeverity(text)
}

// readSyslogLine reads a line that starts with a priority, in a file: as the
// wire does.
func (p *parser) readSyslogLine(line, file string) record {
	msg, rd := syslog.Read([]byte(line), file, "file")
	p.reread(&msg, rd)
	return record{msg: msg, start: true, syslog: true, shape: ShapeSyslog}
}

// reread reads again the body of a message the wire parser could only keep as
// text, and keeps what it finds. A standard message is left alone.
func (p *parser) reread(msg *models.SyslogMessage, rd syslog.Reading) {
	if rd.Standard || strings.TrimSpace(rd.Body) == "" {
		return
	}
	r, declared := p.readBody(rd.Body, msg.ReceivedAt)

	if r.hasTime {
		msg.Timestamp = r.msg.Timestamp
	}
	msg.Hostname = r.msg.Hostname
	msg.AppName = r.msg.AppName
	msg.ProcID = r.msg.ProcID
	msg.Message = r.msg.Message
	if r.hasLevel && (declared || !rd.HasPRI) {
		msg.Severity = r.msg.Severity
		msg.SeverityLabel = r.msg.SeverityLabel
	}
}

// readBody reads what follows the priority, or a whole message that has none.
// declared says the level it found was a field of its own, not a word in the
// text: only such a level overrides a priority.
func (p *parser) readBody(body string, receivedAt time.Time) (record, bool) {
	if looksLikeJSON(body) {
		if r := p.parseJSON(body, ""); r.start {
			return r, true
		}
	}
	if r, ok := p.parseNetworkGear(body, receivedAt); ok {
		return r, false
	}
	if r, ok := p.parseShape(body, ""); ok {
		return r, true
	}
	if looksLikeLogfmt(body) {
		return p.parseLogfmt(body, ""), true
	}
	return p.parseWireText(body), false
}

// parseWireText reads a body that is text: a timestamp at the front, then —
// as rsyslog forwards it — a host and a tag, or a tag alone.
func (p *parser) parseWireText(body string) record {
	d := Detect(body, p.year, p.loc)
	r := record{msg: base(d.Rest, body, ""), start: true, shape: ShapePlain}
	if d.HasTime {
		r.msg.Timestamp = d.Timestamp
		r.hasTime = true
	}
	if d.HasHost {
		r.msg.Hostname = d.Host
		r.hasHost = true
	}
	syslog.ExtractTag(&r.msg)
	// Off the wire, a level word in the middle of a sentence is too often just
	// a word: only one at the very front is a level.
	if sev, ok := leadingLevel(r.msg.Message); ok {
		r.msg.Severity = sev
		r.msg.SeverityLabel = models.SeverityToLabel(sev)
		r.hasLevel = true
	}
	return r
}

// leadingLevel reads a level word at the very front of a message — "ERROR
// disk full", "[WARN] queue depth" — and nowhere else.
func leadingLevel(s string) (models.Severity, bool) {
	s = strings.TrimLeft(s, " \t[(<")
	end := strings.IndexAny(s, " \t])>:,|")
	if end < 0 {
		end = len(s)
	}
	sev, ok := severityWords[strings.ToUpper(s[:end])]
	return sev, ok
}

// networkGear is the shape Cisco IOS, IOS-XE, NX-OS and ASA write after the
// priority:
//
//	123: *Oct 27 09:14:02.123: %LINK-3-UPDOWN: Interface Gi0/1, changed state to down
//	123: R1: Oct 27 2026 09:14:02 CET: %SYS-5-CONFIG_I: Configured from console
//	Oct 27 2026 09:14:02: %ASA-6-302013: Built outbound TCP connection …
//	Oct 27 2026 09:14:02 FW-01 : %ASA-4-106023: Deny tcp …
//	%LINK-3-UPDOWN: Interface Gi0/1, changed state to down
//
// A sequence number, a hostname, a timestamp (starred or dotted when the clock
// is not synchronised, with a year and a zone when configured), and the
// mnemonic, which carries the severity and names what logged it.
var networkGear = regexp.MustCompile(
	`^(?:\d+: )?` +
		`(?:([A-Za-z][\w.-]*): )?` +
		`(?:[*.]?([A-Z][a-z]{2} +\d{1,2}(?: \d{4})? \d{2}:\d{2}:\d{2}(?:\.\d{1,6})?)(?: [A-Z]{2,5})?(?: ([A-Za-z][\w.-]*) ?)?: )?` +
		`(%[A-Z][A-Z0-9_]*-([0-7])-[A-Z0-9_]+): ?(.*)$`)

// Tried on the stamp with its spaces collapsed: IOS pads a one-digit day.
var networkGearLayouts = []string{"Jan 2 2006 15:04:05.999999", "Jan 2 15:04:05.999999"}

func (p *parser) parseNetworkGear(body string, receivedAt time.Time) (record, bool) {
	m := networkGear.FindStringSubmatch(body)
	if m == nil {
		return record{}, false
	}
	host, stamp, deviceID, mnemonic, level, text := m[1], m[2], m[3], m[4], m[5], m[6]
	r := record{msg: base(text, body, ""), start: true, shape: ShapeSyslog}
	r.msg.AppName = mnemonic
	r.msg.ProcID = ""
	r.msg.Message = text
	if host == "" {
		host = deviceID
	}
	r.msg.Hostname = host
	r.hasHost = host != ""
	if stamp != "" {
		stamp = strings.Join(strings.Fields(stamp), " ")
		for _, layout := range networkGearLayouts {
			t, err := time.ParseInLocation(layout, stamp, p.loc)
			if err != nil {
				continue
			}
			if t.Year() == 0 {
				t = syslog.ResolveBSDYear(t, receivedAt)
			}
			r.msg.Timestamp, r.hasTime = t, true
			break
		}
	}
	if sev, ok := levelFromString(level); ok {
		r.msg.Severity = sev
		r.msg.SeverityLabel = models.SeverityToLabel(sev)
		r.hasLevel = true
	}
	return r, true
}
