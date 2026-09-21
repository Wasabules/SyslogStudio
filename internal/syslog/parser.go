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
	rawStr := strings.TrimRight(string(raw), "\n\r\x00")

	msg := models.SyslogMessage{
		ID:         uuid.New().String(),
		ReceivedAt: time.Now(),
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
		return msg
	}

	// Must start with '<'
	if rawStr[0] != '<' {
		msg.Message = rawStr
		msg.Severity = models.SevNotice
		msg.SeverityLabel = models.SeverityToLabel(models.SevNotice)
		msg.Facility = models.FacUser
		msg.FacilityLabel = models.FacilityToLabel(models.FacUser)
		msg.Timestamp = msg.ReceivedAt
		return msg
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
		return msg
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
		return msg
	}

	msg.Severity = severity
	msg.SeverityLabel = models.SeverityToLabel(severity)
	msg.Facility = facility
	msg.FacilityLabel = models.FacilityToLabel(facility)

	remainder := rawStr[closeIdx+1:]

	// Try RFC 5424: starts with version number (typically "1 ")
	if len(remainder) > 1 && remainder[0] >= '1' && remainder[0] <= '9' && remainder[1] == ' ' {
		if parseRFC5424(remainder, &msg) {
			return msg
		}
	}

	// Fall back to RFC 3164
	parseRFC3164(remainder, &msg)
	return msg
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
func parseRFC3164(remainder string, msg *models.SyslogMessage) {
	msg.Version = 0

	if len(remainder) == 0 {
		msg.Message = ""
		msg.Timestamp = msg.ReceivedAt
		return
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
				return
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
		return
	}

	// Skip leading space
	remainder = strings.TrimLeft(remainder, " ")

	if len(remainder) == 0 {
		return
	}

	// Next token is hostname (until space)
	spaceIdx := strings.Index(remainder, " ")
	if spaceIdx < 0 {
		msg.Hostname = clone(remainder)
		return
	}

	msg.Hostname = clone(remainder[:spaceIdx])
	remainder = remainder[spaceIdx+1:]

	// The rest is the MSG part. RFC 3164 MSG = TAG MSG
	// TAG is typically "appname[pid]:" or "appname:"
	msg.Message = clone(remainder)
	extractAppFromMsg(msg)
}

// extractAppFromMsg tries to extract app name and PID from the message TAG field.
// Common format: "appname[pid]: message" or "appname: message"
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
