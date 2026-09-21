package syslog

import (
	"strings"
	"testing"
	"time"

	"SyslogStudio/internal/models"
)

// --- RFC 5424 Tests ---

func TestParse_RFC5424_FullFormat(t *testing.T) {
	raw := []byte(`<165>1 2023-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut="3" eventSource="Application" eventID="1011"] An application event log entry`)
	msg := Parse(raw, "192.168.1.100", "UDP")

	// PRI 165 = facility 20 (local4), severity 5 (notice)
	if msg.Facility != models.FacLocal4 {
		t.Errorf("expected facility Local4 (%d), got %d", models.FacLocal4, msg.Facility)
	}
	if msg.Severity != models.SevNotice {
		t.Errorf("expected severity Notice (%d), got %d", models.SevNotice, msg.Severity)
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

	if msg.Facility != models.FacAuth {
		t.Errorf("expected facility Auth (%d), got %d", models.FacAuth, msg.Facility)
	}
	if msg.Severity != models.SevCritical {
		t.Errorf("expected severity Critical (%d), got %d", models.SevCritical, msg.Severity)
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
	if msg.Facility != models.FacUser {
		t.Errorf("expected facility User (%d), got %d", models.FacUser, msg.Facility)
	}
	if msg.Severity != models.SevNotice {
		t.Errorf("expected severity Notice (%d), got %d", models.SevNotice, msg.Severity)
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
	if msg.Facility != models.FacAuth {
		t.Errorf("expected facility Auth (%d), got %d", models.FacAuth, msg.Facility)
	}
	if msg.Severity != models.SevCritical {
		t.Errorf("expected severity Critical (%d), got %d", models.SevCritical, msg.Severity)
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
	// BSD carries no year, so it is inferred from arrival: either the current
	// year or the one before, whichever lands nearer. Asserting now.Year()
	// literally would make this fixture's fixed "Oct 11" fail for half the
	// calendar once that inference exists.
	if y := msg.Timestamp.Year(); y != now.Year() && y != now.Year()-1 {
		t.Errorf("timestamp year %d is neither the current year nor the one before", y)
	}
	if d := msg.Timestamp.Sub(now); d > 370*24*time.Hour || d < -370*24*time.Hour {
		t.Errorf("timestamp %v is more than a year away from now (%v)", msg.Timestamp, now)
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
	if msg.Severity != models.SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
	if msg.Facility != models.FacUser {
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
	if msg.Severity != models.SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
	if msg.Facility != models.FacUser {
		t.Errorf("expected default facility User, got %d", msg.Facility)
	}
}

func TestParse_InvalidPRI_NonNumeric(t *testing.T) {
	raw := []byte("<abc>some message")
	msg := Parse(raw, "10.0.0.1", "UDP")

	if msg.Severity != models.SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
	if msg.Facility != models.FacUser {
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
	if msg.Severity != models.SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
	if msg.Facility != models.FacUser {
		t.Errorf("expected default facility User, got %d", msg.Facility)
	}
}

func TestParse_InvalidPRI_NegativeValue(t *testing.T) {
	raw := []byte("<-1>some message")
	msg := Parse(raw, "10.0.0.1", "UDP")

	if msg.Severity != models.SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
}

func TestParse_GarbageInput(t *testing.T) {
	raw := []byte("\x00\x01\x02\x03\x04")
	msg := Parse(raw, "10.0.0.1", "UDP")

	// First char is not '<', so treated as plain message
	if msg.Severity != models.SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
}

func TestParse_NoClosingAngleBracket(t *testing.T) {
	raw := []byte("<13 some message without closing bracket")
	msg := Parse(raw, "10.0.0.1", "UDP")

	// closeIdx will be > 4 or < 0, should fall back
	if msg.Severity != models.SevNotice {
		t.Errorf("expected default severity Notice, got %d", msg.Severity)
	}
}

func TestParse_ClosingBracketTooFar(t *testing.T) {
	raw := []byte("<12345>some message")
	msg := Parse(raw, "10.0.0.1", "UDP")

	// closeIdx = 5 which is > 4, should fall back
	if msg.Severity != models.SevNotice {
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
		facility models.Facility
		severity models.Severity
	}{
		{"PRI 0 (kern.emerg)", "<0>1 - - - - - - msg", models.FacKern, models.SevEmergency},
		{"PRI 7 (kern.debug)", "<7>1 - - - - - - msg", models.FacKern, models.SevDebug},
		{"PRI 8 (user.emerg)", "<8>1 - - - - - - msg", models.FacUser, models.SevEmergency},
		{"PRI 191 (local7.debug)", "<191>1 - - - - - - msg", models.FacLocal7, models.SevDebug},
		{"PRI 86 (authpriv.info)", "<86>1 - - - - - - msg", models.FacAuthPriv, models.SevInformational},
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
		facility models.Facility
		severity models.Severity
	}{
		{"0", models.FacKern, models.SevEmergency},
		{"13", models.FacUser, models.SevNotice},
		{"34", models.FacAuth, models.SevCritical},
		{"165", models.FacLocal4, models.SevNotice},
		{"191", models.FacLocal7, models.SevDebug},
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
		expectSeverity models.Severity
		expectFacility models.Facility
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
			expectSeverity: models.SevInformational,
			expectFacility: models.FacUser,
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
			expectSeverity: models.SevInformational,
			expectFacility: models.FacAuth,
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
			expectSeverity: models.SevNotice,
			expectFacility: models.FacUser,
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
			expectSeverity: models.SevNotice,
			expectFacility: models.FacUser,
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
			expectSeverity: models.SevInformational,
			expectFacility: models.FacUser,
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
			msg := &models.SyslogMessage{Message: tc.input}
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
		severity models.Severity
		label    string
	}{
		{models.SevEmergency, "Emergency"},
		{models.SevAlert, "Alert"},
		{models.SevCritical, "Critical"},
		{models.SevError, "Error"},
		{models.SevWarning, "Warning"},
		{models.SevNotice, "Notice"},
		{models.SevInformational, "Info"},
		{models.SevDebug, "Debug"},
		{models.Severity(99), "Unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			got := models.SeverityToLabel(tc.severity)
			if got != tc.label {
				t.Errorf("SeverityToLabel(%d) = %q, want %q", tc.severity, got, tc.label)
			}
		})
	}
}

func TestFacilityToLabel(t *testing.T) {
	tests := []struct {
		facility models.Facility
		label    string
	}{
		{models.FacKern, "kern"},
		{models.FacUser, "user"},
		{models.FacMail, "mail"},
		{models.FacDaemon, "daemon"},
		{models.FacAuth, "auth"},
		{models.FacSyslog, "syslog"},
		{models.FacLPR, "lpr"},
		{models.FacNews, "news"},
		{models.FacUUCP, "uucp"},
		{models.FacCron, "cron"},
		{models.FacAuthPriv, "authpriv"},
		{models.FacFTP, "ftp"},
		{models.FacNTP, "ntp"},
		{models.FacAudit, "audit"},
		{models.FacAlert, "alert"},
		{models.FacClock, "clock"},
		{models.FacLocal0, "local0"},
		{models.FacLocal1, "local1"},
		{models.FacLocal2, "local2"},
		{models.FacLocal3, "local3"},
		{models.FacLocal4, "local4"},
		{models.FacLocal5, "local5"},
		{models.FacLocal6, "local6"},
		{models.FacLocal7, "local7"},
		{models.Facility(99), "unknown"},
	}
	for _, tc := range tests {
		t.Run(tc.label, func(t *testing.T) {
			got := models.FacilityToLabel(tc.facility)
			if got != tc.label {
				t.Errorf("FacilityToLabel(%d) = %q, want %q", tc.facility, got, tc.label)
			}
		})
	}
}

// RFC 3164 carries no zone. Reading it as UTC — what time.Parse does with a
// zone-less layout — shifted every BSD-framed message by the collector's UTC
// offset, which is what issue #24 reported as "exactly two hours".
//
// These assertions are written against the wall clock and time.Local rather
// than a fixed offset, so they hold wherever they run, CI's UTC included.
func TestParse_RFC3164_UsesLocalZone(t *testing.T) {
	raw := []byte("<189>Sep 17 20:26:32 firewall.example.net date=2026-09-17 time=20:26:32")
	msg := Parse(raw, "10.211.8.13", "TLS")

	if got := msg.Timestamp.Location(); got != time.Local {
		t.Errorf("timestamp is in %v, want the collector's local zone", got)
	}
	// The wall clock must read back exactly what the device sent.
	if got := msg.Timestamp.Format("01-02 15:04:05"); got != "09-17 20:26:32" {
		t.Errorf("wall clock = %s, want 09-17 20:26:32", got)
	}
}

// RFC 5424 timestamps carry their own offset, and it must be preserved rather
// than reinterpreted — the fix for the BSD path must not touch this one.
func TestParse_RFC5424_PreservesExplicitOffset(t *testing.T) {
	msg := Parse([]byte("<34>1 2026-09-17T20:26:32+02:00 host app - - - hello"), "10.0.0.1", "UDP")

	want := time.Date(2026, 9, 17, 18, 26, 32, 0, time.UTC)
	if !msg.Timestamp.Equal(want) {
		t.Errorf("timestamp = %v, want the same instant as %v", msg.Timestamp, want)
	}
}

func TestResolveBSDYear(t *testing.T) {
	// The BSD stamp has no year, so it is dated from when it arrived.
	tests := []struct {
		name       string
		stamp      string // month-day hh:mm:ss, as parsed (year zero)
		receivedAt string
		wantYear   int
	}{
		{"same day", "06-15 12:00:00", "2026-06-15T12:00:01", 2026},
		{"a few hours before arrival", "06-15 08:00:00", "2026-06-15T12:00:00", 2026},
		// A device still sending December 31st, received on January 1st: dating
		// it from the arrival year would put it eleven months in the future.
		{"new year rollover", "12-31 23:59:00", "2027-01-01T00:05:00", 2026},
		// The mirror case: a device whose clock has already rolled over sends
		// "Jan 01" while the collector is still in December.
		{"sender rolled over early", "01-01 00:05:00", "2026-12-31T23:59:00", 2027},
		// Clock drift and eastward time zones legitimately put the sender's
		// wall clock ahead; a few weeks of drift must not cost a year.
		{"sender slightly ahead", "06-15 18:00:00", "2026-06-15T12:00:00", 2026},
		{"sender ahead by under a day", "06-16 10:00:00", "2026-06-15T12:00:00", 2026},
		{"sender weeks ahead", "10-11 22:14:15", "2026-09-22T12:00:00", 2026},
		// A log arriving months late still belongs to the year it arrived in,
		// because that year is the nearer of the two.
		{"months late", "01-15 09:00:00", "2026-09-22T12:00:00", 2026},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := time.ParseInLocation("01-02 15:04:05", tt.stamp, time.Local)
			if err != nil {
				t.Fatalf("test fixture: %v", err)
			}
			received, err := time.ParseInLocation("2006-01-02T15:04:05", tt.receivedAt, time.Local)
			if err != nil {
				t.Fatalf("test fixture: %v", err)
			}

			got := resolveBSDYear(parsed, received)
			if got.Year() != tt.wantYear {
				t.Errorf("year = %d, want %d (stamp %s received %s)", got.Year(), tt.wantYear, tt.stamp, tt.receivedAt)
			}
			// The wall clock itself must survive untouched.
			if got.Format("01-02 15:04:05") != tt.stamp {
				t.Errorf("wall clock = %s, want %s", got.Format("01-02 15:04:05"), tt.stamp)
			}
		})
	}
}

// A message whose year rolls over must still come out ordered before its
// arrival, which is the property the correction exists to preserve.
func TestResolveBSDYear_NeverFarInTheFuture(t *testing.T) {
	received := time.Date(2027, 1, 1, 0, 5, 0, 0, time.Local)
	parsed := time.Date(0, 12, 31, 23, 59, 0, 0, time.Local)

	got := resolveBSDYear(parsed, received)
	if got.After(received) {
		t.Errorf("stamped %v, which is after arrival at %v", got, received)
	}
}
