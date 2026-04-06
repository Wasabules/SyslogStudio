package syslog

import (
	"sync"
	"testing"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
)

// --- matchesFilter Tests ---

func TestMatchesFilter_EmptyFilter(t *testing.T) {
	msg := models.SyslogMessage{
		Severity: models.SevError,
		Facility: models.FacAuth,
		Hostname: "myhost",
		AppName:  "myapp",
		SourceIP: "10.0.0.1",
		Message:  "test message",
	}
	filter := models.FilterCriteria{}

	if !matchesFilter(msg, filter) {
		t.Error("empty filter should match all messages")
	}
}

func TestMatchesFilter_Severities(t *testing.T) {
	msg := models.SyslogMessage{Severity: models.SevError}

	tests := []struct {
		name       string
		severities []int
		want       bool
	}{
		{"matching severity", []int{int(models.SevError)}, true},
		{"non-matching severity", []int{int(models.SevWarning)}, false},
		{"multiple with match", []int{int(models.SevWarning), int(models.SevError), int(models.SevCritical)}, true},
		{"multiple without match", []int{int(models.SevWarning), int(models.SevDebug)}, false},
		{"empty severity list", []int{}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := models.FilterCriteria{Severities: tc.severities}
			got := matchesFilter(msg, filter)
			if got != tc.want {
				t.Errorf("matchesFilter with severities %v: got %v, want %v", tc.severities, got, tc.want)
			}
		})
	}
}

func TestMatchesFilter_Facilities(t *testing.T) {
	msg := models.SyslogMessage{Facility: models.FacAuth}

	tests := []struct {
		name       string
		facilities []int
		want       bool
	}{
		{"matching facility", []int{int(models.FacAuth)}, true},
		{"non-matching facility", []int{int(models.FacKern)}, false},
		{"multiple with match", []int{int(models.FacKern), int(models.FacAuth), int(models.FacMail)}, true},
		{"multiple without match", []int{int(models.FacKern), int(models.FacMail)}, false},
		{"empty facility list", []int{}, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := models.FilterCriteria{Facilities: tc.facilities}
			got := matchesFilter(msg, filter)
			if got != tc.want {
				t.Errorf("matchesFilter with facilities %v: got %v, want %v", tc.facilities, got, tc.want)
			}
		})
	}
}

func TestMatchesFilter_Hostname(t *testing.T) {
	msg := models.SyslogMessage{Hostname: "WebServer-Prod-01"}

	tests := []struct {
		name     string
		hostname string
		want     bool
	}{
		{"exact match", "WebServer-Prod-01", true},
		{"case insensitive", "webserver-prod-01", true},
		{"partial match", "Prod", true},
		{"partial lower", "prod", true},
		{"no match", "staging", false},
		{"empty filter", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := models.FilterCriteria{Hostname: tc.hostname}
			got := matchesFilter(msg, filter)
			if got != tc.want {
				t.Errorf("matchesFilter hostname=%q: got %v, want %v", tc.hostname, got, tc.want)
			}
		})
	}
}

func TestMatchesFilter_AppName(t *testing.T) {
	msg := models.SyslogMessage{AppName: "nginx"}

	tests := []struct {
		name    string
		appName string
		want    bool
	}{
		{"exact match", "nginx", true},
		{"case insensitive", "NGINX", true},
		{"partial match", "ngi", true},
		{"no match", "apache", false},
		{"empty filter", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := models.FilterCriteria{AppName: tc.appName}
			got := matchesFilter(msg, filter)
			if got != tc.want {
				t.Errorf("matchesFilter appName=%q: got %v, want %v", tc.appName, got, tc.want)
			}
		})
	}
}

func TestMatchesFilter_SourceIP(t *testing.T) {
	msg := models.SyslogMessage{SourceIP: "192.168.1.100"}

	tests := []struct {
		name     string
		sourceIP string
		want     bool
	}{
		{"exact match", "192.168.1.100", true},
		{"partial match prefix", "192.168", true},
		{"partial match suffix", "1.100", true},
		{"no match", "10.0.0.1", false},
		{"empty filter", "", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := models.FilterCriteria{SourceIP: tc.sourceIP}
			got := matchesFilter(msg, filter)
			if got != tc.want {
				t.Errorf("matchesFilter sourceIP=%q: got %v, want %v", tc.sourceIP, got, tc.want)
			}
		})
	}
}

func TestMatchesFilter_Search(t *testing.T) {
	msg := models.SyslogMessage{
		Message:    "Connection refused from client",
		RawMessage: "<13>Oct 11 22:14:15 host app: Connection refused from client",
	}

	tests := []struct {
		name   string
		search string
		want   bool
	}{
		{"match in message", "refused", true},
		{"case insensitive", "REFUSED", true},
		{"match in raw", "<13>Oct", true},
		{"no match", "accepted", false},
		{"empty search", "", true},
		{"partial word", "connect", true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			filter := models.FilterCriteria{Search: tc.search}
			got := matchesFilter(msg, filter)
			if got != tc.want {
				t.Errorf("matchesFilter search=%q: got %v, want %v", tc.search, got, tc.want)
			}
		})
	}
}

func TestMatchesFilter_CombinedFilters(t *testing.T) {
	msg := models.SyslogMessage{
		Severity: models.SevError,
		Facility: models.FacAuth,
		Hostname: "webserver",
		AppName:  "sshd",
		SourceIP: "10.0.0.5",
		Message:  "Failed password for root",
	}

	tests := []struct {
		name   string
		filter models.FilterCriteria
		want   bool
	}{
		{
			"all matching",
			models.FilterCriteria{
				Severities: []int{int(models.SevError)},
				Facilities: []int{int(models.FacAuth)},
				Hostname:   "web",
				AppName:    "sshd",
				SourceIP:   "10.0",
				Search:     "root",
			},
			true,
		},
		{
			"severity mismatch",
			models.FilterCriteria{
				Severities: []int{int(models.SevWarning)},
				Hostname:   "web",
			},
			false,
		},
		{
			"facility mismatch",
			models.FilterCriteria{
				Facilities: []int{int(models.FacKern)},
				Hostname:   "web",
			},
			false,
		},
		{
			"hostname mismatch",
			models.FilterCriteria{
				Severities: []int{int(models.SevError)},
				Hostname:   "dbserver",
			},
			false,
		},
		{
			"search mismatch",
			models.FilterCriteria{
				Severities: []int{int(models.SevError)},
				Search:     "accepted",
			},
			false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := matchesFilter(msg, tc.filter)
			if got != tc.want {
				t.Errorf("matchesFilter: got %v, want %v", got, tc.want)
			}
		})
	}
}

// --- Ring Buffer Tests ---

func TestNewSyslogServer_Defaults(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	if server == nil {
		t.Fatal("NewSyslogServer returned nil")
	}
	if server.config.MaxBuffer != 10000 {
		t.Errorf("expected MaxBuffer 10000, got %d", server.config.MaxBuffer)
	}
	if len(server.messages) != 10000 {
		t.Errorf("expected message buffer length 10000, got %d", len(server.messages))
	}
	if server.head != 0 {
		t.Errorf("expected head 0, got %d", server.head)
	}
	if server.count != 0 {
		t.Errorf("expected count 0, got %d", server.count)
	}
	if server.stats == nil {
		t.Error("expected non-nil stats collector")
	}
	if server.tlsManager == nil {
		t.Error("expected non-nil TLS manager")
	}
}

func TestAddMessage_FillsBuffer(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	// Use a small buffer for testing
	server.messages = make([]models.SyslogMessage, 5)

	msg1 := models.SyslogMessage{ID: "1", Message: "first"}
	msg2 := models.SyslogMessage{ID: "2", Message: "second"}
	msg3 := models.SyslogMessage{ID: "3", Message: "third"}

	server.addMessage(msg1)
	server.addMessage(msg2)
	server.addMessage(msg3)

	if server.count != 3 {
		t.Errorf("expected count 3, got %d", server.count)
	}
	if server.head != 3 {
		t.Errorf("expected head 3, got %d", server.head)
	}
	if server.messages[0].ID != "1" {
		t.Errorf("expected messages[0].ID='1', got %q", server.messages[0].ID)
	}
	if server.messages[1].ID != "2" {
		t.Errorf("expected messages[1].ID='2', got %q", server.messages[1].ID)
	}
	if server.messages[2].ID != "3" {
		t.Errorf("expected messages[2].ID='3', got %q", server.messages[2].ID)
	}
}

func TestAddMessage_WrapsAround(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	// Small buffer: capacity 3
	server.messages = make([]models.SyslogMessage, 3)

	// Fill buffer completely
	server.addMessage(models.SyslogMessage{ID: "1", Message: "first"})
	server.addMessage(models.SyslogMessage{ID: "2", Message: "second"})
	server.addMessage(models.SyslogMessage{ID: "3", Message: "third"})

	if server.count != 3 {
		t.Errorf("expected count 3, got %d", server.count)
	}
	if server.head != 0 {
		t.Errorf("expected head 0 (wrapped), got %d", server.head)
	}

	// Add one more - should overwrite the oldest (message "1")
	server.addMessage(models.SyslogMessage{ID: "4", Message: "fourth"})

	if server.count != 3 {
		t.Errorf("expected count still 3 (buffer full), got %d", server.count)
	}
	if server.head != 1 {
		t.Errorf("expected head 1, got %d", server.head)
	}

	// messages[0] should now be "4" (overwrote "1")
	if server.messages[0].ID != "4" {
		t.Errorf("expected messages[0].ID='4', got %q", server.messages[0].ID)
	}
	// messages[1] should still be "2"
	if server.messages[1].ID != "2" {
		t.Errorf("expected messages[1].ID='2', got %q", server.messages[1].ID)
	}
	// messages[2] should still be "3"
	if server.messages[2].ID != "3" {
		t.Errorf("expected messages[2].ID='3', got %q", server.messages[2].ID)
	}
}

func TestAddMessage_WrapsMultipleTimes(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	server.messages = make([]models.SyslogMessage, 3)

	// Add 10 messages to a buffer of size 3
	for i := 0; i < 10; i++ {
		server.addMessage(models.SyslogMessage{ID: string(rune('A' + i)), Message: "msg"})
	}

	// Count should cap at 3
	if server.count != 3 {
		t.Errorf("expected count 3, got %d", server.count)
	}

	// head should be at 10 % 3 = 1
	if server.head != 1 {
		t.Errorf("expected head 1, got %d", server.head)
	}
}

func TestAddMessage_PendingBatch(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	server.messages = make([]models.SyslogMessage, 100)

	msg := models.SyslogMessage{ID: "test", Message: "hello"}
	server.addMessage(msg)

	server.mu.Lock()
	pendingLen := len(server.pendingBatch)
	server.mu.Unlock()

	if pendingLen != 1 {
		t.Errorf("expected 1 pending message, got %d", pendingLen)
	}
}

func TestAddMessage_PendingBatchCappedAtMaxPendingBatch(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	// Need buffer at least maxPendingBatch + 100 big
	server.messages = make([]models.SyslogMessage, maxPendingBatch+100)

	// Add more than maxPendingBatch messages
	for i := 0; i < maxPendingBatch+100; i++ {
		server.addMessage(models.SyslogMessage{ID: "x", Message: "m"})
	}

	server.mu.Lock()
	pendingLen := len(server.pendingBatch)
	server.mu.Unlock()

	if pendingLen != maxPendingBatch {
		t.Errorf("expected pending batch capped at %d, got %d", maxPendingBatch, pendingLen)
	}
}

// --- GetMessages with filter Tests ---

func TestGetMessages_NoFilter(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	server.messages = make([]models.SyslogMessage, 10)

	server.addMessage(models.SyslogMessage{ID: "1", Message: "one", Severity: models.SevError})
	server.addMessage(models.SyslogMessage{ID: "2", Message: "two", Severity: models.SevWarning})
	server.addMessage(models.SyslogMessage{ID: "3", Message: "three", Severity: models.SevDebug})

	result := server.GetMessages(models.FilterCriteria{})

	if len(result) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(result))
	}
	// Messages should be in order oldest to newest
	if result[0].ID != "1" {
		t.Errorf("expected first message ID='1', got %q", result[0].ID)
	}
	if result[2].ID != "3" {
		t.Errorf("expected last message ID='3', got %q", result[2].ID)
	}
}

func TestGetMessages_WithSeverityFilter(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	server.messages = make([]models.SyslogMessage, 10)

	server.addMessage(models.SyslogMessage{ID: "1", Severity: models.SevError})
	server.addMessage(models.SyslogMessage{ID: "2", Severity: models.SevWarning})
	server.addMessage(models.SyslogMessage{ID: "3", Severity: models.SevError})
	server.addMessage(models.SyslogMessage{ID: "4", Severity: models.SevDebug})

	result := server.GetMessages(models.FilterCriteria{
		Severities: []int{int(models.SevError)},
	})

	if len(result) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(result))
	}
	if result[0].ID != "1" || result[1].ID != "3" {
		t.Errorf("expected messages 1 and 3, got %q and %q", result[0].ID, result[1].ID)
	}
}

func TestGetMessages_WithSearchFilter(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	server.messages = make([]models.SyslogMessage, 10)

	server.addMessage(models.SyslogMessage{ID: "1", Message: "Login failed", RawMessage: "raw1"})
	server.addMessage(models.SyslogMessage{ID: "2", Message: "Login successful", RawMessage: "raw2"})
	server.addMessage(models.SyslogMessage{ID: "3", Message: "Disk full", RawMessage: "raw3"})

	result := server.GetMessages(models.FilterCriteria{Search: "login"})

	if len(result) != 2 {
		t.Fatalf("expected 2 messages matching 'login', got %d", len(result))
	}
}

func TestGetMessages_WrappedBuffer(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	server.messages = make([]models.SyslogMessage, 3)

	// Fill and wrap
	server.addMessage(models.SyslogMessage{ID: "1"})
	server.addMessage(models.SyslogMessage{ID: "2"})
	server.addMessage(models.SyslogMessage{ID: "3"})
	server.addMessage(models.SyslogMessage{ID: "4"}) // overwrites "1"

	result := server.GetMessages(models.FilterCriteria{})

	if len(result) != 3 {
		t.Fatalf("expected 3 messages, got %d", len(result))
	}
	// Should be in order: 2, 3, 4 (oldest to newest)
	if result[0].ID != "2" {
		t.Errorf("expected first message ID='2', got %q", result[0].ID)
	}
	if result[1].ID != "3" {
		t.Errorf("expected second message ID='3', got %q", result[1].ID)
	}
	if result[2].ID != "4" {
		t.Errorf("expected third message ID='4', got %q", result[2].ID)
	}
}

func TestGetMessages_EmptyBuffer(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	result := server.GetMessages(models.FilterCriteria{})

	if len(result) != 0 {
		t.Errorf("expected 0 messages from empty buffer, got %d", len(result))
	}
}

// --- ClearMessages Tests ---

func TestClearMessages(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	server.messages = make([]models.SyslogMessage, 10)

	server.addMessage(models.SyslogMessage{ID: "1", Message: "one"})
	server.addMessage(models.SyslogMessage{ID: "2", Message: "two"})

	server.ClearMessages()

	if server.count != 0 {
		t.Errorf("expected count 0 after clear, got %d", server.count)
	}
	if server.head != 0 {
		t.Errorf("expected head 0 after clear, got %d", server.head)
	}

	result := server.GetMessages(models.FilterCriteria{})
	if len(result) != 0 {
		t.Errorf("expected 0 messages after clear, got %d", len(result))
	}
}

// --- GetStatus Tests ---

func TestGetStatus_Initial(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	status := server.GetStatus()

	if status.Running {
		t.Error("expected not running initially")
	}
	if status.UDPRunning {
		t.Error("expected UDP not running initially")
	}
	if status.TCPRunning {
		t.Error("expected TCP not running initially")
	}
	if status.TLSRunning {
		t.Error("expected TLS not running initially")
	}
}

// --- GetStats via Server Tests ---

func TestGetStats_ViaServer(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	server.messages = make([]models.SyslogMessage, 100)

	// Manually add messages (bypasses Parse)
	server.addMessage(models.SyslogMessage{ID: "1", SeverityLabel: "Error", Hostname: "host1"})
	server.addMessage(models.SyslogMessage{ID: "2", SeverityLabel: "Error", Hostname: "host1"})
	server.addMessage(models.SyslogMessage{ID: "3", SeverityLabel: "Warning", Hostname: "host2"})

	stats := server.GetStats()

	if stats.TotalMessages != 3 {
		t.Errorf("expected TotalMessages 3, got %d", stats.TotalMessages)
	}
	if stats.BufferUsed != 3 {
		t.Errorf("expected BufferUsed 3, got %d", stats.BufferUsed)
	}
	if stats.BufferMax != 100 {
		t.Errorf("expected BufferMax 100, got %d", stats.BufferMax)
	}
}

// --- MockEventEmitter behavior Tests ---

func TestMockEventEmitter_RecordsEmissions(t *testing.T) {
	emitter := event.NewMockEventEmitter()

	emitter.Emit("test:event", "data1", 42)
	emitter.Emit("test:other", true)

	events := emitter.GetEvents()
	if len(events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(events))
	}

	if events[0].Name != "test:event" {
		t.Errorf("expected event name 'test:event', got %q", events[0].Name)
	}
	if len(events[0].Data) != 2 {
		t.Errorf("expected 2 data items, got %d", len(events[0].Data))
	}

	if events[1].Name != "test:other" {
		t.Errorf("expected event name 'test:other', got %q", events[1].Name)
	}
}

func TestMockEventEmitter_Clear(t *testing.T) {
	emitter := event.NewMockEventEmitter()

	emitter.Emit("event1")
	emitter.Emit("event2")
	emitter.Clear()

	events := emitter.GetEvents()
	if len(events) != 0 {
		t.Errorf("expected 0 events after clear, got %d", len(events))
	}
}

func TestMockEventEmitter_ConcurrentSafe(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	var wg sync.WaitGroup

	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			emitter.Emit("concurrent", i)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			_ = emitter.GetEvents()
		}
	}()

	wg.Wait()

	events := emitter.GetEvents()
	if len(events) != 100 {
		t.Errorf("expected 100 events, got %d", len(events))
	}
}

// --- processMessage integration ---

func TestProcessMessage_Integration(t *testing.T) {
	emitter := event.NewMockEventEmitter()
	server := NewSyslogServer(emitter, nil)

	server.messages = make([]models.SyslogMessage, 10)

	// Process a real syslog message through the server
	raw := []byte("<34>Oct 11 22:14:15 myhost sshd[1234]: Failed login")
	server.processMessage(raw, "192.168.1.1", "TCP")

	if server.count != 1 {
		t.Fatalf("expected count 1, got %d", server.count)
	}

	msgs := server.GetMessages(models.FilterCriteria{})
	if len(msgs) != 1 {
		t.Fatalf("expected 1 message, got %d", len(msgs))
	}

	msg := msgs[0]
	if msg.Hostname != "myhost" {
		t.Errorf("expected hostname 'myhost', got %q", msg.Hostname)
	}
	if msg.AppName != "sshd" {
		t.Errorf("expected appName 'sshd', got %q", msg.AppName)
	}
	if msg.SourceIP != "192.168.1.1" {
		t.Errorf("expected sourceIP '192.168.1.1', got %q", msg.SourceIP)
	}
	if msg.Protocol != "TCP" {
		t.Errorf("expected protocol 'TCP', got %q", msg.Protocol)
	}
}
