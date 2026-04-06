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
		t, err := time.Parse("Jan  2 15:04:05", tsStr)
		if err != nil {
			t, err = time.Parse("Jan 2 15:04:05", tsStr[:14])
			if err != nil {
				// No valid timestamp, treat entire remainder as message
				msg.Timestamp = msg.ReceivedAt
				msg.Message = remainder
				extractAppFromMsg(msg)
				return
			}
			// Set year to current year
			now := time.Now()
			t = t.AddDate(now.Year()-t.Year(), 0, 0)
			msg.Timestamp = t
			remainder = remainder[14:]
		} else {
			now := time.Now()
			t = t.AddDate(now.Year()-t.Year(), 0, 0)
			msg.Timestamp = t
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
