package main

import (
	"strings"
	"testing"
	"time"
)

// --- RFC 5424 Tests ---

func TestParse_RFC5424_FullFormat(t *testing.T) {
	raw := []byte(`<165>1 2023-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry`)
	msg := Parse(raw, "192.168.1.100", "UDP")

	// PRI 165 = facility 20 (local4), severity 5 (notice)
	if msg.Facility != FacLocal4 {
		t.Errorf("expected facility Local4 (%d), got %d", FacLocal4, msg.Facility)
	}
	if msg.Severity != SevNotice {
		t.Errorf("expected severity Notice (%d), got %d", SevNotice, msg.Severity)
	}
	if msg.SeverityLabel != "Notice" {
		t.Errorf("expected severity label 'Notice', got %q", msg.SeverityLabel)
	}
	if msg.FacilityLabel != "local4" {
		t.Errorf("expected facility label 'local4', got %q", msg.FacilityLabel)
	}
	if msg.Version != 1 {
		t.Errorf("expected version 1, got %d", msg.Version)
	}
	if msg.Hostname != "mymachine.example.com" {
		t.Errorf("expected hostname 'mymachine.example.com', got %q", msg.Hostname)
	}
	if msg.AppName != "evntslog" {
		t.Errorf("expected appName 'evntslog', got %q", msg.AppName)
	}
	if msg.ProcID != "" {
		t.Errorf("expected empty procID (nil value), got %q", msg.ProcID)
	}
	if msg.MsgID != "ID47" {
		t.Errorf("expected msgID 'ID47', got %q", msg.MsgID)
	}
	expectedSD := `[exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"]`
	if msg.StructuredData != expectedSD {
		t.Errorf("expected structuredData %q, got %q", expectedSD, msg.StructuredData)
	}
	if msg.Message != "An application event log entry" {
		t.Errorf("expected message 'An application event log entry', got %q", msg.Message)
	}
	if msg.SourceIP != "192.168.1.100" {
		t.Errorf("expected sourceIP '192.168.1.100', got %q", msg.SourceIP)
	}
	if msg.Protocol != "UDP" {
		t.Errorf("expected protocol 'UDP', got %q", msg.Protocol)
	}
	if msg.ID == "" {
		t.Error("expected non-empty ID")
	}

	// Verify timestamp was parsed
	expectedTime := time.Date(2023, 10, 11, 22, 14, 15, 3000000, time.UTC)
	if !msg.Timestamp.Equal(expectedTime) {
		t.Errorf("expected timestamp %v, got %v", expectedTime, msg.Timestamp)
	}
}

func TestParse_RFC5424_WithStructuredData(t *testing.T) {
	raw := []byte(`<34>1 2023-10-11T22:14:15.003Z myhost app 1234 msgid123 [sd1@123 key="val"][sd2@456 k2="v2"] The message`)
	msg := Parse(raw, "10.0.0.1", "TCP")

	if msg.Facility != FacAuth {
		t.Errorf("expected facility Auth (%d), got %d", FacAuth, msg.Facility)
	}
	if msg.Severity != SevCritical {
		t.Errorf("expected severity Critical (%d), got %d", SevCritical, msg.Severity)
	}
	if msg.Hostname != "myhost" {
		t.Errorf("expected hostname 'myhost', got %q", msg.Hostname)
	}
	if msg.AppName != "app" {
		t.Errorf("expected appName 'app', got %q", msg.AppName)
	}
	if msg.ProcID != "1234" {
		t.Errorf("expected procID '1234', got %q", msg.ProcID)
	}
	if msg.MsgID != "msgid123" {
		t.Errorf("expected msgID 'msgid123', got %q", msg.MsgID)
	}
	expectedSD := `[sd1@123 key="val"][sd2@456 k2="v2"]`
	if msg.StructuredData != expectedSD {
		t.Errorf("expected structuredData %q, got %q", expectedSD, msg.StructuredData)
	}
	if msg.Message != "The message" {
		t.Errorf("expected message 'The message', got %q", msg.Message)
	}
}

func TestParse_RFC5424_AllNilValues(t *testing.T) {
	raw := []byte(`<13>1 - - - - - - The message body`)
	msg := Parse(raw, "10.0.0.1", "UDP")

	// PRI 13 = facility 1 (user), severity 5 (notice)
	if msg.Facility != FacUser {
		t.Errorf("expected facility User (%d), got %d", FacUser, msg.Facility)
	}
	if msg.Severity != SevNotice {
		t.Errorf("expected severity Notice (%d), got %d", SevNotice, msg.Severity)
	}
	if msg.Hostname != "" {
		t.Errorf("expected empty hostname, got %q", msg.Hostname)
	}
	if msg.AppName != "" {
		t.Errorf("expected empty appName, got %q", msg.AppName)
	}
	if msg.ProcID != "" {
		t.Errorf("expected empty procID, got %q", msg.ProcID)
	}
	if msg.MsgID != "" {
		t.Errorf("expected empty msgID, got %q", msg.MsgID)
	}
	if msg.StructuredData != "" {
		t.Errorf("expected empty structuredData, got %q", msg.StructuredData)
	}
	if msg.Message != "The message body" {
		t.Errorf("expected message 'The message body', got %q", msg.Message)
	}
	// Timestamp should fall back to ReceivedAt when "-"
	if msg.Timestamp.IsZero() {
		t.Error("expected non-zero timestamp (fallback to ReceivedAt)")
	}
}

func TestParse_RFC5424_NoStructuredDataNoMessage(t *testing.T) {
	raw := []byte(`<14>1 2023-10-11T22:14:15Z host app pid mid -`)
	msg := Parse(raw, "10.0.0.1", "UDP")

	if msg.Version != 1 {
		t.Errorf("expected version 1, got %d", msg.Version)
	}
	if msg.StructuredData != "" {
		t.Errorf("expected empty structuredData, got %q", msg.StructuredData)
	}
	if msg.Message != "" {
		t.Errorf("expected empty message, got %q", msg.Message)
	}
}

func TestParse_RFC5424_BOMInMessage(t *testing.T) {
	raw := []byte("<14>1 2023-10-11T22:14:15Z host app pid mid - \xef\xbb\xbfBOM message")
	msg := Parse(raw, "10.0.0.1", "UDP")

	if msg.Message != "BOM message" {
		t.Errorf("expected BOM-stripped message 'BOM message', got %q", msg.Message)
	}
}

func TestParse_RFC5424_RFC3339NanoTimestamp(t *testing.T) {
	raw := []byte(`<14>1 2023-10-11T22:14:15.123456789Z host app - - - msg`)
	msg := Parse(raw, "10.0.0.1", "UDP")

	expected := time.Date(2023, 10, 11, 22, 14, 15, 123456789, time.UTC)
	if !msg.Timestamp.Equal(expected) {
		t.Errorf("expected timestamp %v, got %v", expected, msg.Timestamp)
	}
}

// --- RFC 3164 / BSD Tests ---

func TestParse_RFC3164_WithPID(t *testing.T) {
	now := time.Now()
	raw := []byte("<34>Oct 11 22:14:15 mymachine sshd[1234]: Failed password for user")
	msg := Parse(raw, "192.168.1.1", "TCP")

	if msg.Version != 0 {
		t.Errorf("expected version 0 (BSD), got %d", msg.Version)
	}
	if msg.Facility != FacAuth {
		t.Errorf("expected facility Auth (%d), got %d", FacAuth, msg.Facility)
	}
	if msg.Severity != SevCritical {
		t.Errorf("expected severity Critical (%d), got %d", SevCritical, msg.Severity)
	}
	if msg.Hostname != "mymachine" {
		t.Errorf("expected hostname 'mymachine', got %q", msg.Hostname)
	}
	if msg.AppName != "sshd" {
		t.Errorf("expected appName 'sshd', got %q", msg.AppName)
	}
	if msg.ProcID != "1234" {
		t.Errorf("expected procID '1234', got %q", msg.ProcID)
	}
	if msg.Message != "Failed password for user" {
		t.Errorf("expected message 'Failed password for user', got %q", msg.Message)
	}
	// Timestamp year should be current year since BSD doesn't include year
	if msg.Timestamp.Year() != now.Year() {
		t.Errorf("expected timestamp year %d, got %d", now.Year(), msg.Timestamp.Year())
	}
}

func TestParse_RFC3164_WithoutPID(t *testing.T) {
	raw := []byte("<13>Oct 11 22:14:15 myhost myapp: Something happened")
	msg := Parse(raw, "10.0.0.5", "UDP")

	if msg.Hostname != "myhost" {
		t.Errorf("expected hostname 'myhost', got %q", msg.Hostname)
	}
	if msg.AppName != "myapp" {
		t.Errorf("expected appName 'myapp', got %q", msg.AppName)
	}
	if msg.ProcID != "" {
		t.Errorf("expected empty procID, got %q", msg.ProcID)
	}
	if msg.Message != "Something happened" {
		t.Errorf("expected message 'Something happened', got %q", msg.Message)
	}
}

func TestParse_RFC3164_SingleDigitDay(t *testing.T) {
	raw := []byte("<13>Oct  1 22:14:15 myhost myapp: Message")
	msg := Parse(raw, "10.0.0.5", "UDP")

	if msg.Hostname != "myhost" {
		t.Errorf("expected hostname 'myhost', got %q", msg.Hostname)
	}
	if msg.Timestamp.Day() != 1 {
		t.Errorf("expected day 1, got %d", msg.Timestamp.Day())
	}
}

func TestParse_RFC3164_OnlyHostname(t *testing.T) {
	raw := []byte("<13>Oct 11 22:14:15 myhostonly")
	msg := Parse(raw, "10.0.0.5", "UDP")

	if msg.Hostname != "myhostonly" {
		t.Errorf("expected hostname 'myhostonly', got %q", msg.Hostname)
	}
	if msg.Message != "" {
		t.Errorf("expected empty message, got %q", msg.Message)
	}
}

// --- Empty / Malformed Messages ---

func TestParse_EmptyString(t *testing.T) {
	msg := Parse([]byte(""), "10.0.0.1", "UDP")

	if msg.Message != "" {
		t.Errorf("expected empty message, got %q", msg.Message)
	}
	if msg.Severity != SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
	if msg.Facility != FacUser {
		t.Errorf("expected default facility User, got %d", msg.Facility)
	}
	if msg.SourceIP != "10.0.0.1" {
		t.Errorf("expected sourceIP '10.0.0.1', got %q", msg.SourceIP)
	}
}

func TestParse_NoPRI(t *testing.T) {
	raw := []byte("This is a message with no PRI")
	msg := Parse(raw, "10.0.0.1", "UDP")

	if msg.Message != "This is a message with no PRI" {
		t.Errorf("expected raw as message, got %q", msg.Message)
	}
	if msg.Severity != SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
	if msg.Facility != FacUser {
		t.Errorf("expected default facility User, got %d", msg.Facility)
	}
}

func TestParse_InvalidPRI_NonNumeric(t *testing.T) {
	raw := []byte("<abc>some message")
	msg := Parse(raw, "10.0.0.1", "UDP")

	if msg.Severity != SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
	if msg.Facility != FacUser {
		t.Errorf("expected default facility User, got %d", msg.Facility)
	}
	if msg.Message != "<abc>some message" {
		t.Errorf("expected raw string as message, got %q", msg.Message)
	}
}

func TestParse_InvalidPRI_OutOfRange(t *testing.T) {
	raw := []byte("<192>some message")
	msg := Parse(raw, "10.0.0.1", "UDP")

	// 192 is out of range (max 191), should fall back
	if msg.Severity != SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
	if msg.Facility != FacUser {
		t.Errorf("expected default facility User, got %d", msg.Facility)
	}
}

func TestParse_InvalidPRI_NegativeValue(t *testing.T) {
	raw := []byte("<-1>some message")
	msg := Parse(raw, "10.0.0.1", "UDP")

	if msg.Severity != SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
}

func TestParse_GarbageInput(t *testing.T) {
	raw := []byte("\x00\x01\x02\x03\x04")
	msg := Parse(raw, "10.0.0.1", "UDP")

	// First char is not '<', so treated as plain message
	if msg.Severity != SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
}

func TestParse_NoClosingAngleBracket(t *testing.T) {
	raw := []byte("<13 some message without closing bracket")
	msg := Parse(raw, "10.0.0.1", "UDP")

	// closeIdx will be > 4 or < 0, should fall back
	if msg.Severity != SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
}

func TestParse_ClosingBracketTooFar(t *testing.T) {
	raw := []byte("<12345>some message")
	msg := Parse(raw, "10.0.0.1", "UDP")

	// closeIdx = 5 which is > 4, should fall back
	if msg.Severity != SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
	if msg.Message != "<12345>some message" {
		t.Errorf("expected raw as message, got %q", msg.Message)
	}
}

func TestParse_TrailingNewlineStripped(t *testing.T) {
	raw := []byte("<13>Oct 11 22:14:15 host app: msg\n\r\x00")
	msg := Parse(raw, "10.0.0.1", "UDP")

	if strings.ContainsAny(msg.RawMessage, "\n\r\x00") {
		t.Errorf("expected trailing newline/null stripped from RawMessage, got %q", msg.RawMessage)
	}
}

// --- Edge cases ---

func TestParse_VeryLongMessage(t *testing.T) {
	longPayload := strings.Repeat("A", 100000)
	raw := []byte("<13>1 2023-10-11T22:14:15Z host app - - - " + longPayload)
	msg := Parse(raw, "10.0.0.1", "UDP")

	if msg.Message != longPayload {
		t.Errorf("expected long message of length %d, got length %d", len(longPayload), len(msg.Message))
	}
}

func TestParse_SpecialCharactersInMessage(t *testing.T) {
	raw := []byte(`<13>1 2023-10-11T22:14:15Z host app - - - Special chars: <>&"'\/tabs	and spaces`)
	msg := Parse(raw, "10.0.0.1", "UDP")

	expected := "Special chars: <>&\"'\\/tabs\tand spaces"
	if msg.Message != expected {
		t.Errorf("expected message %q, got %q", expected, msg.Message)
	}
}

func TestParse_PRIBoundaryValues(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		facility Facility
		severity Severity
	}{
		{"PRI 0 (kern.emerg)", "<0>1 - - - - - - msg", FacKern, SevEmergency},
		{"PRI 7 (kern.debug)", "<7>1 - - - - - - msg", FacKern, SevDebug},
		{"PRI 8 (user.emerg)", "<8>1 - - - - - - msg", FacUser, SevEmergency},
		{"PRI 191 (local7.debug)", "<191>1 - - - - - - msg", FacLocal7, SevDebug},
		{"PRI 86 (authpriv.info)", "<86>1 - - - - - - msg", FacAuthPriv, SevInformational},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := Parse([]byte(tc.raw), "10.0.0.1", "UDP")
			if msg.Facility != tc.facility {
				t.Errorf("expected facility %d, got %d", tc.facility, msg.Facility)
			}
			if msg.Severity != tc.severity {
				t.Errorf("expected severity %d, got %d", tc.severity, msg.Severity)
			}
		})
	}
}

// --- parsePriority() Tests ---

func TestParsePriority_Valid(t *testing.T) {
	tests := []struct {
		priStr   string
		facility Facility
		severity Severity
	}{
		{"0", FacKern, SevEmergency},
		{"13", FacUser, SevNotice},
		{"34", FacAuth, SevCritical},
		{"165", FacLocal4, SevNotice},
		{"191", FacLocal7, SevDebug},
	}

	for _, tc := range tests {
		t.Run("PRI_"+tc.priStr, func(t *testing.T) {
			fac, sev, err := parsePriority(tc.priStr)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if fac != tc.facility {
				t.Errorf("expected facility %d, got %d", tc.facility, fac)
			}
			if sev != tc.severity {
				t.Errorf("expected severity %d, got %d", tc.severity, sev)
			}
		})
	}
}

func TestParsePriority_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		priStr string
	}{
		{"empty string", ""},
		{"non-numeric", "abc"},
		{"negative", "-1"},
		{"too large", "192"},
		{"way too large", "999"},
		{"floating point", "13.5"},
		{"spaces", " 13 "},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := parsePriority(tc.priStr)
			if err == nil {
				t.Errorf("expected error for priStr %q, got nil", tc.priStr)
			}
		})
	}
}

// --- findSDEnd() Tests ---

func TestFindSDEnd(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int
	}{
		{"simple SD", `[exampleSDID@123 key="val"]`, 26},
		{"multiple SD", `[sd1@1 k="v"][sd2@2 k="v"]`, 25},
		{"escaped quote in SD", `[sd@1 k="v\"al"]`, 15},
		{"no SD", `not structured data`, -1},
		{"unclosed bracket", `[sd@1 k="val"`, -1},
		{"empty brackets", `[]`, 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := findSDEnd(tc.input)
			if result != tc.expected {
				t.Errorf("findSDEnd(%q) = %d, want %d", tc.input, result, tc.expected)
			}
		})
	}
}

// --- Table-driven Parse tests ---

func TestParse_TableDriven(t *testing.T) {
	tests := []struct {
		name           string
		raw            string
		sourceIP       string
		protocol       string
		expectVersion  int
		expectSeverity Severity
		expectFacility Facility
		expectHostname string
		expectAppName  string
		expectMessage  string
	}{
		{
			name:           "RFC5424 minimal",
			raw:            "<14>1 - - - - - - hello",
			sourceIP:       "127.0.0.1",
			protocol:       "UDP",
			expectVersion:  1,
			expectSeverity: SevInformational,
			expectFacility: FacUser,
			expectHostname: "",
			expectAppName:  "",
			expectMessage:  "hello",
		},
		{
			name:           "RFC3164 typical",
			raw:            "<38>Jan 15 10:30:00 webserver nginx: GET /index.html 200",
			sourceIP:       "10.0.0.2",
			protocol:       "TCP",
			expectVersion:  0,
			expectSeverity: SevInformational,
			expectFacility: FacAuth,
			expectHostname: "webserver",
			expectAppName:  "nginx",
			expectMessage:  "GET /index.html 200",
		},
		{
			name:           "plain text no PRI",
			raw:            "Just a plain text message",
			sourceIP:       "10.0.0.3",
			protocol:       "UDP",
			expectVersion:  0,
			expectSeverity: SevNotice,
			expectFacility: FacUser,
			expectHostname: "",
			expectAppName:  "",
			expectMessage:  "Just a plain text message",
		},
		{
			name:           "empty after PRI (RFC3164 path, empty remainder)",
			raw:            "<13>",
			sourceIP:       "10.0.0.1",
			protocol:       "UDP",
			expectVersion:  0,
			expectSeverity: SevNotice,
			expectFacility: FacUser,
			expectHostname: "",
			expectAppName:  "",
			expectMessage:  "",
		},
		{
			name:           "TLS protocol recorded",
			raw:            "<14>1 2023-10-11T22:14:15Z host app - - - msg",
			sourceIP:       "172.16.0.1",
			protocol:       "TLS",
			expectVersion:  1,
			expectSeverity: SevInformational,
			expectFacility: FacUser,
			expectHostname: "host",
			expectAppName:  "app",
			expectMessage:  "msg",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := Parse([]byte(tc.raw), tc.sourceIP, tc.protocol)

			if msg.Version != tc.expectVersion {
				t.Errorf("version: got %d, want %d", msg.Version, tc.expectVersion)
			}
			if msg.Severity != tc.expectSeverity {
				t.Errorf("severity: got %d, want %d", msg.Severity, tc.expectSeverity)
			}
			if msg.Facility != tc.expectFacility {
				t.Errorf("facility: got %d, want %d", msg.Facility, tc.expectFacility)
			}
			if msg.Hostname != tc.expectHostname {
				t.Errorf("hostname: got %q, want %q", msg.Hostname, tc.expectHostname)
			}
			if msg.AppName != tc.expectAppName {
				t.Errorf("appName: got %q, want %q", msg.AppName, tc.expectAppName)
			}
			if msg.Message != tc.expectMessage {
				t.Errorf("message: got %q, want %q", msg.Message, tc.expectMessage)
			}
			if msg.SourceIP != tc.sourceIP {
				t.Errorf("sourceIP: got %q, want %q", msg.SourceIP, tc.sourceIP)
			}
			if msg.Protocol != tc.protocol {
				t.Errorf("protocol: got %q, want %q", msg.Protocol, tc.protocol)
			}
			if msg.ID == "" {
				t.Error("expected non-empty ID")
			}
			if msg.ReceivedAt.IsZero() {
				t.Error("expected non-zero ReceivedAt")
			}
		})
	}
}

// --- extractAppFromMsg Tests ---

func TestExtractAppFromMsg(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantApp    string
		wantProcID string
		wantMsg    string
	}{
		{
			name:       "app with PID",
			input:      "sshd[1234]: Connection closed",
			wantApp:    "sshd",
			wantProcID: "1234",
			wantMsg:    "Connection closed",
		},
		{
			name:       "app without PID",
			input:      "myapp: Something happened",
			wantApp:    "myapp",
			wantProcID: "",
			wantMsg:    "Something happened",
		},
		{
			name:       "no colon",
			input:      "no colon in this message",
			wantApp:    "",
			wantProcID: "",
			wantMsg:    "no colon in this message",
		},
		{
			name:       "colon too far",
			input:      strings.Repeat("a", 50) + ": too far",
			wantApp:    "",
			wantProcID: "",
			wantMsg:    strings.Repeat("a", 50) + ": too far",
		},
		{
			name:       "empty message",
			input:      "",
			wantApp:    "",
			wantProcID: "",
			wantMsg:    "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := &SyslogMessage{Message: tc.input}
			extractAppFromMsg(msg)

			if msg.AppName != tc.wantApp {
				t.Errorf("appName: got %q, want %q", msg.AppName, tc.wantApp)
			}
			if msg.ProcID != tc.wantProcID {
				t.Errorf("procID: got %q, want %q", msg.ProcID, tc.wantProcID)
			}
			if msg.Message != tc.wantMsg {
				t.Errorf("message: got %q, want %q", msg.Message, tc.wantMsg)
			}
		})
	}
}

// --- SeverityToLabel and FacilityToLabel Tests ---

func TestSeverityToLabel(t *testing.T) {
	tests := []struct {
		severity Severity
		label    string
	}{
		{SevEmergency, "Emergency"},
		{SevAlert, "Alert"},
		{SevCritical, "Critical"},
		{SevError, "Error"},
		{SevWarning, "Warning"},
		{SevNotice, "Notice"},
		{SevInformational, "Info"},
		{SevDebug, "Debug"},
		{Severity(99), "Unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			got := SeverityToLabel(tc.severity)
			if got != tc.label {
				t.Errorf("SeverityToLabel(%d) = %q, want %q", tc.severity, got, tc.label)
			}
		})
	}
}

func TestFacilityToLabel(t *testing.T) {
	tests := []struct {
		facility Facility
		label    string
	}{
		{FacKern, "kern"},
		{FacUser, "user"},
		{FacMail, "mail"},
		{FacDaemon, "daemon"},
		{FacAuth, "auth"},
		{FacSyslog, "syslog"},
		{FacLPR, "lpr"},
		{FacNews, "news"},
		{FacUUCP, "uucp"},
		{FacCron, "cron"},
		{FacAuthPriv, "authpriv"},
		{FacFTP, "ftp"},
		{FacNTP, "ntp"},
		{FacAudit, "audit"},
		{FacAlert, "alert"},
		{FacClock, "clock"},
		{FacLocal0, "local0"},
		{FacLocal1, "local1"},
		{FacLocal2, "local2"},
		{FacLocal3, "local3"},
		{FacLocal4, "local4"},
		{FacLocal5, "local5"},
		{FacLocal6, "local6"},
		{FacLocal7, "local7"},
		{Facility(99), "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			got := FacilityToLabel(tc.facility)
			if got != tc.label {
				t.Errorf("FacilityToLabel(%d) = %q, want %q", tc.facility, got, tc.label)
			}
		})
	}
}
