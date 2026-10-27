package syslog

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"SyslogStudio/internal/models"
)

// clone creates an independent copy of a string, releasing the original backing array.
// This prevents substring references from keeping large parent strings alive in memory.
func clone(s string) string {
	return strings.Clone(s)
}

// Parse attempts to parse a raw syslog message. Tries RFC 5424 first, then RFC 3164.
func Parse(raw []byte, sourceIP string, protocol string) models.SyslogMessage {
	msg, _ := Read(raw, sourceIP, protocol)
	return msg
}

// Reading says how a message was read: what a more tolerant reader needs to
// know before reading it again (importer.WireReader).
type Reading struct {
	// HasPRI is a valid <PRI> in front. Its severity and facility are then
	// the sender's own, and the message's.
	HasPRI bool
	// Standard is a header this parser reads as an RFC defines it: an RFC
	// 5424 one, or an RFC 3164 timestamp followed by a space. What is not —
	// an ISO timestamp with no version, JSON, key=value, a Cisco sequence
	// number — this parser can only keep as text.
	Standard bool
	// Body is what follows the PRI, or the whole message when there is none.
	Body string
}

// Read is Parse, saying how the message was read.
func Read(raw []byte, sourceIP string, protocol string) (models.SyslogMessage, Reading) {
	return ReadAt(raw, sourceIP, protocol, time.Now())
}

// ReadAt is Read for a message that arrived at a given time: a stored one,
// read again. The arrival stands in for a missing timestamp and gives an
// RFC 3164 stamp its year.
func ReadAt(raw []byte, sourceIP string, protocol string, at time.Time) (models.SyslogMessage, Reading) {
	rawStr := strings.TrimRight(string(raw), "\n\r\x00")

	msg := models.SyslogMessage{
		ID:         uuid.New().String(),
		ReceivedAt: at,
		SourceIP:   sourceIP,
		Protocol:   protocol,
		RawMessage: rawStr,
	}

	if len(rawStr) == 0 {
		msg.Message = ""
		msg.Severity = models.SevNotice
		msg.SeverityLabel = models.SeverityToLabel(models.SevNotice)
		msg.Facility = models.FacUser
		msg.FacilityLabel = models.FacilityToLabel(models.FacUser)
		msg.Timestamp = msg.ReceivedAt
		return msg, Reading{}
	}

	// Must start with '<'
	if rawStr[0] != '<' {
		msg.Message = rawStr
		msg.Severity = models.SevNotice
		msg.SeverityLabel = models.SeverityToLabel(models.SevNotice)
		msg.Facility = models.FacUser
		msg.FacilityLabel = models.FacilityToLabel(models.FacUser)
		msg.Timestamp = msg.ReceivedAt
		return msg, Reading{Body: rawStr}
	}

	// Extract PRI
	closeIdx := strings.Index(rawStr, ">")
	if closeIdx < 0 || closeIdx > 4 {
		msg.Message = rawStr
		msg.Severity = models.SevNotice
		msg.SeverityLabel = models.SeverityToLabel(models.SevNotice)
		msg.Facility = models.FacUser
		msg.FacilityLabel = models.FacilityToLabel(models.FacUser)
		msg.Timestamp = msg.ReceivedAt
		return msg, Reading{Body: rawStr}
	}

	priStr := rawStr[1:closeIdx]
	facility, severity, err := parsePriority(priStr)
	if err != nil {
		msg.Message = rawStr
		msg.Severity = models.SevNotice
		msg.SeverityLabel = models.SeverityToLabel(models.SevNotice)
		msg.Facility = models.FacUser
		msg.FacilityLabel = models.FacilityToLabel(models.FacUser)
		msg.Timestamp = msg.ReceivedAt
		return msg, Reading{Body: rawStr}
	}

	msg.Severity = severity
	msg.SeverityLabel = models.SeverityToLabel(severity)
	msg.Facility = facility
	msg.FacilityLabel = models.FacilityToLabel(facility)

	remainder := rawStr[closeIdx+1:]

	// Try RFC 5424: starts with version number (typically "1 ")
	if len(remainder) > 1 && remainder[0] >= '1' && remainder[0] <= '9' && remainder[1] == ' ' {
		if parseRFC5424(remainder, &msg) {
			return msg, Reading{HasPRI: true, Standard: true, Body: remainder}
		}
	}

	// Fall back to RFC 3164
	standard := parseRFC3164(remainder, &msg)
	return msg, Reading{HasPRI: true, Standard: standard, Body: remainder}
}

// parsePriority extracts facility and severity from the PRI value.
// PRI = Facility * 8 + Severity
func parsePriority(priStr string) (models.Facility, models.Severity, error) {
	pri, err := strconv.Atoi(priStr)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid PRI: %s", priStr)
	}
	if pri < 0 || pri > 191 {
		return 0, 0, fmt.Errorf("PRI out of range: %d", pri)
	}
	facility := models.Facility(pri / 8)
	severity := models.Severity(pri % 8)
	return facility, severity, nil
}

// parseRFC5424 parses an RFC 5424 formatted message.
// Format: VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID SP STRUCTURED-DATA [SP MSG]
func parseRFC5424(remainder string, msg *models.SyslogMessage) bool {
	msg.Version = 1

	parts := strings.SplitN(remainder, " ", 7)
	if len(parts) < 7 {
		return false
	}

	// parts[0] = version (already consumed detection)
	// parts[1] = timestamp
	// parts[2] = hostname
	// parts[3] = app-name
	// parts[4] = procid
	// parts[5] = msgid
	// parts[6] = structured-data + message

	// Parse timestamp
	tsStr := parts[1]
	if tsStr == "-" {
		msg.Timestamp = msg.ReceivedAt
	} else {
		t, err := time.Parse(time.RFC3339Nano, tsStr)
		if err != nil {
			t, err = time.Parse(time.RFC3339, tsStr)
			if err != nil {
				msg.Timestamp = msg.ReceivedAt
			} else {
				msg.Timestamp = t
			}
		} else {
			msg.Timestamp = t
		}
	}

	// Hostname
	if parts[2] != "-" {
		msg.Hostname = clone(parts[2])
	}

	// App-Name
	if parts[3] != "-" {
		msg.AppName = clone(parts[3])
	}

	// ProcID
	if parts[4] != "-" {
		msg.ProcID = clone(parts[4])
	}

	// MsgID
	if parts[5] != "-" {
		msg.MsgID = clone(parts[5])
	}

	// Structured-Data + Message
	sdAndMsg := parts[6]
	if strings.HasPrefix(sdAndMsg, "-") {
		msg.StructuredData = ""
		if len(sdAndMsg) > 1 && sdAndMsg[1] == ' ' {
			msg.Message = clone(sdAndMsg[2:])
		} else {
			msg.Message = ""
		}
	} else if strings.HasPrefix(sdAndMsg, "[") {
		sdEnd := findSDEnd(sdAndMsg)
		if sdEnd >= 0 {
			msg.StructuredData = clone(sdAndMsg[:sdEnd+1])
			if sdEnd+2 < len(sdAndMsg) {
				msg.Message = clone(sdAndMsg[sdEnd+2:])
			}
		} else {
			msg.Message = clone(sdAndMsg)
		}
	} else {
		msg.Message = clone(sdAndMsg)
	}

	// Strip BOM from message
	msg.Message = strings.TrimPrefix(msg.Message, "\xef\xbb\xbf")

	return true
}

// findSDEnd finds the index of the closing ']' of structured data,
// handling quoted strings inside SD elements.
func findSDEnd(s string) int {
	depth := 0
	inQuote := false
	escaped := false

	for i := 0; i < len(s); i++ {
		if escaped {
			escaped = false
			continue
		}
		ch := s[i]
		switch {
		case ch == '\\' && inQuote:
			escaped = true
		case ch == '"':
			inQuote = !inQuote
		case ch == '[' && !inQuote:
			depth++
		case ch == ']' && !inQuote:
			depth--
			if depth == 0 {
				// Check if there are more SD elements
				if i+1 < len(s) && s[i+1] == '[' {
					continue
				}
				return i
			}
		}
	}
	return -1
}

// resolveBSDYear gives an RFC 3164 timestamp its year. The BSD format carries
// month, day and time but no year and no zone, so parseRFC3164 reads it in the
// collector's local zone — the same assumption rsyslog and syslog-ng make, and
// the one that matches reality when sender and collector sit in the same zone.
// Reading it as UTC instead, which is what time.Parse does with a zone-less
// layout, shifted every BSD-framed message by the collector's UTC offset: two
// hours for a CEST host (issue #24).
//
// The year is inferred from arrival, trying the arrival year and both of its
// neighbours. The choice is deliberately asymmetric, because a log is emitted
// before it is received: a stamp in the past is ordinary — a device buffering,
// a relay catching up, a clock running slow — while a stamp in the future can
// only be clock skew. So candidates more than maxClockSkewAhead past the
// arrival time are discarded, and the nearest of what remains wins.
//
// That is what separates the two New Year cases from an ordinary late log. A
// device still sending "Dec 31 23:59" on January 1st lands in the year that
// just ended; one whose clock already rolled over to "Jan 01" while the
// collector is still in December lands in the year about to start, since it is
// only minutes ahead. But "Jan 15" arriving in September stays in the current
// year rather than jumping to next January, which is four months of skew and
// far less likely than a log that is simply months late.
func resolveBSDYear(t, receivedAt time.Time) time.Time {
	return ResolveBSDYear(t, receivedAt)
}

// ResolveBSDYear gives a timestamp that carries no year — a BSD one — the year
// nearest to its arrival, as described above. Exported for the readers that
// meet such stamps in shapes this parser does not read (importer.WireReader).
func ResolveBSDYear(t, receivedAt time.Time) time.Time {
	if receivedAt.IsZero() {
		receivedAt = time.Now()
	}
	var best time.Time
	for _, year := range []int{receivedAt.Year() - 1, receivedAt.Year(), receivedAt.Year() + 1} {
		candidate := time.Date(year, t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
		if candidate.Sub(receivedAt) > maxClockSkewAhead {
			continue
		}
		if best.IsZero() || absDuration(candidate.Sub(receivedAt)) < absDuration(best.Sub(receivedAt)) {
			best = candidate
		}
	}
	if best.IsZero() {
		// Unreachable in practice: the previous year is always in the past.
		return time.Date(receivedAt.Year(), t.Month(), t.Day(),
			t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), t.Location())
	}
	return best
}

// maxClockSkewAhead is how far ahead of arrival a BSD stamp may sit before its
// year is treated as wrong rather than its clock. Generous on purpose: devices
// with no NTP drift by days, and one a few zones east legitimately reports a
// wall clock ahead of the collector's. A month is well beyond either, and well
// short of the gap that distinguishes a New Year crossing.
const maxClockSkewAhead = 31 * 24 * time.Hour

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// parseRFC3164 parses a BSD-style syslog message.
// Format: TIMESTAMP HOSTNAME MSG (after PRI is stripped)
//
// It reports whether the header was the RFC's: a timestamp followed by a
// space. What is not is kept as text here, and read again by whoever knows
// more shapes than this parser does.
func parseRFC3164(remainder string, msg *models.SyslogMessage) bool {
	return readBSD(remainder, msg, true)
}

// RereadWithoutHost reads an RFC 3164 message again for a device that sends
// no hostname: the word after the timestamp, taken for one, is the start of
// the tag or the text. Any other message is left as it is.
func RereadWithoutHost(msg *models.SyslogMessage, rd Reading) {
	if !rd.Standard || msg.Version != 0 || msg.Hostname == "" {
		return
	}
	m := *msg
	m.Hostname, m.AppName, m.ProcID, m.Message = "", "", "", ""
	readBSD(rd.Body, &m, false)
	m.Timestamp = msg.Timestamp
	*msg = m
}

// readBSD is parseRFC3164, the host read or not.
func readBSD(remainder string, msg *models.SyslogMessage, withHost bool) bool {
	msg.Version = 0

	if len(remainder) == 0 {
		msg.Message = ""
		msg.Timestamp = msg.ReceivedAt
		return true
	}

	// Try to parse BSD timestamp: "Mmm dd hh:mm:ss" or "Mmm  d hh:mm:ss"
	// Minimum length: "Jan  1 00:00:00" = 15 characters
	if len(remainder) >= 15 {
		tsStr := remainder[:15]
		t, err := time.ParseInLocation("Jan  2 15:04:05", tsStr, time.Local)
		if err != nil {
			t, err = time.ParseInLocation("Jan 2 15:04:05", tsStr[:14], time.Local)
			if err != nil {
				// No valid timestamp, treat entire remainder as message
				msg.Timestamp = msg.ReceivedAt
				msg.Message = remainder
				extractAppFromMsg(msg)
				return false
			}
			msg.Timestamp = resolveBSDYear(t, msg.ReceivedAt)
			remainder = remainder[14:]
		} else {
			msg.Timestamp = resolveBSDYear(t, msg.ReceivedAt)
			remainder = remainder[15:]
		}
	} else {
		msg.Timestamp = msg.ReceivedAt
		msg.Message = remainder
		extractAppFromMsg(msg)
		return false
	}

	// The RFC's header is the timestamp, a space and the host. A stamp
	// followed by anything else — Cisco's ".123: %LINK-3-UPDOWN" — is
	// another shape, read here as best this parser can.
	standard := remainder == "" || remainder[0] == ' '

	// Skip leading space
	remainder = strings.TrimLeft(remainder, " ")

	if len(remainder) == 0 {
		return standard
	}

	// Next token is hostname (until space)
	spaceIdx := strings.Index(remainder, " ")
	if spaceIdx < 0 {
		if !withHost || isTagToken(remainder) {
			msg.Message = clone(remainder)
			extractAppFromMsg(msg)
			return standard
		}
		msg.Hostname = clone(remainder)
		return standard
	}

	// Many devices leave the host out — "Oct 27 09:14:02 dhcp: lease …" —
	// and what stands in its place is then the tag. A hostname never ends in a
	// colon.
	if !withHost || isTagToken(remainder[:spaceIdx]) {
		msg.Message = clone(remainder)
		extractAppFromMsg(msg)
		return standard
	}

	msg.Hostname = clone(remainder[:spaceIdx])
	remainder = remainder[spaceIdx+1:]

	// The rest is the MSG part. RFC 3164 MSG = TAG MSG
	// TAG is typically "appname[pid]:" or "appname:"
	msg.Message = clone(remainder)
	extractAppFromMsg(msg)
	return standard
}

// isTagToken is a token that ends the way a TAG does — "dhcp:", "sshd[812]:"
// — and so cannot be a hostname. An IPv6 address may end in a colon too, but
// has others before it.
func isTagToken(tok string) bool {
	name, ok := strings.CutSuffix(tok, ":")
	if !ok || name == "" || strings.Contains(name, ":") {
		return false
	}
	if i := strings.IndexByte(name, '['); i >= 0 {
		name = name[:i]
	}
	return plausibleTag(name)
}

// plausibleTag is a name a TAG could be. A JSON key ("{\"level\""), a Cisco
// sequence number ("123") or a key=value pair is the start of a message that
// happens to contain a colon, and filing it as the application put garbage
// in the App column.
func plausibleTag(name string) bool {
	if name == "" || strings.ContainsAny(name, "\"{}=<>") {
		return false
	}
	for _, r := range name {
		if r < '0' || r > '9' {
			return true
		}
	}
	return false // digits only
}

// extractAppFromMsg tries to extract app name and PID from the message TAG field.
// Common format: "appname[pid]: message" or "appname: message"
// ExtractTag pulls an RFC 3164 TAG — "app[pid]:" or "app:" — off the front of
// a message, filling AppName and ProcID.
//
// Exported for the importer. A file written by rsyslog carries the same TAG as
// a line off the wire does, and a second definition of what a tag looks like
// would drift from this one the first time either changed.
func ExtractTag(msg *models.SyslogMessage) {
	extractAppFromMsg(msg)
}

func extractAppFromMsg(msg *models.SyslogMessage) {
	if msg.Message == "" {
		return
	}

	colonIdx := strings.Index(msg.Message, ":")
	if colonIdx < 0 || colonIdx > 48 {
		return
	}

	tag := msg.Message[:colonIdx]

	// Check for [pid]
	bracketOpen := strings.Index(tag, "[")
	name := tag
	if bracketOpen >= 0 {
		name = tag[:bracketOpen]
	}
	if !plausibleTag(name) {
		return
	}
	if bracketOpen >= 0 {
		bracketClose := strings.Index(tag, "]")
		if bracketClose > bracketOpen {
			msg.AppName = clone(tag[:bracketOpen])
			msg.ProcID = clone(tag[bracketOpen+1 : bracketClose])
		}
	} else {
		// No PID, just app name
		if !strings.Contains(tag, " ") {
			msg.AppName = clone(tag)
		}
	}

	// Trim the tag from the message
	if msg.AppName != "" {
		rest := msg.Message[colonIdx+1:]
		msg.Message = clone(strings.TrimLeft(rest, " "))
	}
}
