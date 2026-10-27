// Package sources reads received messages: as the wire reader reads them, then
// as the first source rule that matches says.
//
// A rule is for a device that bends the syslog RFCs further than reading them
// automatically can follow — no hostname, the same priority on everything, a
// format of its own, a clock in another zone, Windows-1252 instead of UTF-8.
// It is applied as the message arrives, before the live view, the database,
// the alert rules and the routing see it: an alert on errors fires on the
// error the device meant. The raw message is kept as it arrived.
package sources

import (
	"fmt"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"golang.org/x/text/encoding/charmap"

	"SyslogStudio/internal/importer"
	"SyslogStudio/internal/models"
	"SyslogStudio/internal/notify"
	"SyslogStudio/internal/search"
	"SyslogStudio/internal/syslog"
)

// Reader reads received messages. It is safe for concurrent use, and its rules
// can be replaced while messages arrive.
type Reader struct {
	wire  *importer.WireReader
	rules atomic.Pointer[[]*rule]
}

// New makes a reader with no rules.
func New() *Reader {
	return &Reader{wire: importer.NewWireReader()}
}

// rule is a SourceRule ready to apply.
type rule struct {
	models.SourceRule
	sources []search.Address
	pattern *regexp.Regexp
	format  *importer.FormatReader
	charmap *charmap.Charmap
}

func compile(r models.SourceRule) (*rule, error) {
	if err := models.ValidateSourceRule(r); err != nil {
		return nil, err
	}
	c := &rule{SourceRule: r}
	for _, s := range r.Match.Sources {
		if strings.TrimSpace(s) == "" {
			continue
		}
		if err := search.CheckAddressEntry(s); err != nil {
			return nil, err
		}
		c.sources = append(c.sources, search.CompileAddress(s, false))
	}
	if p := strings.TrimSpace(r.Match.Pattern); p != "" {
		re, err := models.SafeCompileRegex(p)
		if err != nil {
			return nil, err
		}
		c.pattern = re
	}
	format, err := importer.NewFormatReader(r.Format)
	if err != nil {
		return nil, err
	}
	c.format = format
	switch r.Encoding {
	case models.EncodingWindows1252:
		c.charmap = charmap.Windows1252
	case models.EncodingLatin1:
		c.charmap = charmap.ISO8859_1
	case models.EncodingLatin9:
		c.charmap = charmap.ISO8859_15
	}
	return c, nil
}

// Compile says what is wrong with a rule, as SetRules would.
func Compile(r models.SourceRule) error {
	_, err := compile(r)
	return err
}

// SetRules replaces the rules, in the order they are tried. Disabled ones are
// kept out; one that does not compile is reported, and the others still apply.
func (r *Reader) SetRules(rules []models.SourceRule) error {
	var compiled []*rule
	var errs []string
	for _, sr := range rules {
		if !sr.Enabled {
			continue
		}
		c, err := compile(sr)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", sr.Name, err))
			continue
		}
		compiled = append(compiled, c)
	}
	r.rules.Store(&compiled)
	if len(errs) > 0 {
		return fmt.Errorf("source rules not applied: %s", strings.Join(errs, "; "))
	}
	return nil
}

// Read reads one message received from sourceIP over protocol.
func (r *Reader) Read(raw []byte, sourceIP, protocol string) models.SyslogMessage {
	return r.ReadAt(raw, sourceIP, protocol, time.Now())
}

// ReadAt is Read for a message that arrived at a given time: a stored one,
// read again with the rules as they are now.
func (r *Reader) ReadAt(raw []byte, sourceIP, protocol string, at time.Time) models.SyslogMessage {
	msg, rd := syslog.ReadAt(raw, sourceIP, protocol, at)
	pri := msg.Severity
	r.wire.Reread(&msg, rd)
	rules := r.rules.Load()
	if rules == nil {
		return msg
	}
	for _, c := range *rules {
		if c.matches(msg) {
			return r.apply(c, raw, msg, rd, pri)
		}
	}
	return msg
}

func (c *rule) matches(msg models.SyslogMessage) bool {
	m := c.Match
	return search.MatchAddresses(c.sources, msg.SourceIP) &&
		notify.MatchesGlob(m.Hostnames, msg.Hostname) &&
		notify.MatchesGlob(m.AppNames, msg.AppName) &&
		(c.pattern == nil || c.pattern.MatchString(msg.RawMessage))
}

// apply reads msg as the rule says. The rule was chosen on the message as
// read before it: a device that does not send UTF-8 is read again, decoded,
// before the rest.
func (r *Reader) apply(c *rule, raw []byte, msg models.SyslogMessage, rd syslog.Reading, pri models.Severity) models.SyslogMessage {
	if c.charmap != nil && !utf8.Valid(raw) {
		if decoded, err := c.charmap.NewDecoder().Bytes(raw); err == nil {
			id := msg.ID
			msg, rd = syslog.ReadAt(decoded, msg.SourceIP, msg.Protocol, msg.ReceivedAt)
			msg.ID = id
			pri = msg.Severity
			r.wire.Reread(&msg, rd)
		}
	}

	// A device that sends no hostname: what was taken for one was not.
	if c.NoHostname {
		syslog.RereadWithoutHost(&msg, rd)
	}

	// An RFC 3164 stamp carries no zone, and was read in this machine's: the
	// device's wall clock is in the rule's. A time the format reads below is
	// read in it too.
	if loc := c.format.Location(); loc != time.Local && rd.Standard && rd.HasPRI && msg.Version == 0 {
		t := msg.Timestamp.In(time.Local)
		msg.Timestamp = time.Date(t.Year(), t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), loc)
	}
	c.format.Reread(&msg, rd)

	switch c.LevelFrom {
	case models.LevelFromPriority:
		if rd.HasPRI {
			setSeverity(&msg, pri)
		}
	case models.LevelFromMessage:
		if msg.Severity == pri {
			if sev, ok := importer.FindLevel(msg.Message); ok {
				setSeverity(&msg, sev)
			}
		}
	}

	switch {
	case c.HostnameFromSource, c.NoHostname && strings.TrimSpace(msg.Hostname) == "":
		msg.Hostname = msg.SourceIP
	case strings.TrimSpace(c.Hostname) != "":
		msg.Hostname = strings.TrimSpace(c.Hostname)
	}
	if a := strings.TrimSpace(c.AppName); a != "" {
		msg.AppName = a
	}
	if c.ArrivalTime {
		msg.Timestamp = msg.ReceivedAt
	}
	msg.ReadBy = c.Name
	return msg
}

func setSeverity(msg *models.SyslogMessage, sev models.Severity) {
	msg.Severity = sev
	msg.SeverityLabel = models.SeverityToLabel(sev)
}

// Try reads samples without any rule and with r, enabled or not, and says
// which it matched: what the rule editor shows before a rule is saved.
func Try(sr models.SourceRule, samples []models.SourceSample) ([]models.SourceTrial, error) {
	c, err := compile(sr)
	if err != nil {
		return nil, err
	}
	reader := New()
	out := make([]models.SourceTrial, 0, len(samples))
	for _, s := range samples {
		raw := []byte(s.Raw)
		msg, rd := syslog.Read(raw, s.SourceIP, s.Protocol)
		pri := msg.Severity
		reader.wire.Reread(&msg, rd)
		trial := models.SourceTrial{Before: msg, After: msg}
		if c.matches(msg) {
			trial.Matched = true
			trial.After = reader.apply(c, raw, msg, rd, pri)
		}
		out = append(out, trial)
	}
	return out, nil
}
