package alert

import (
	"testing"
	"time"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
)

func newTestAlertManager() *AlertManager {
	emitter := event.NewMockEventEmitter()
	return NewAlertManager(emitter)
}

func makeMsg(severity models.Severity, hostname, appName, message string) models.SyslogMessage {
	return models.SyslogMessage{
		ID:            "test-id",
		Severity:      severity,
		SeverityLabel: models.SeverityToLabel(severity),
		Hostname:      hostname,
		AppName:       appName,
		Message:       message,
		RawMessage:    message,
		Timestamp:     time.Now(),
	}
}

func TestAlertManager_AddRule(t *testing.T) {
	am := newTestAlertManager()
	rule := am.AddRule(models.AlertRule{Name: "test", Enabled: true, Pattern: "error"})
	if rule.ID == "" {
		t.Fatal("expected generated ID")
	}
	rules := am.GetRules()
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "test" {
		t.Fatalf("expected name 'test', got '%s'", rules[0].Name)
	}
}

func TestAlertManager_UpdateRule(t *testing.T) {
	am := newTestAlertManager()
	rule := am.AddRule(models.AlertRule{Name: "original", Enabled: true})
	rule.Name = "updated"
	if !am.UpdateRule(rule) {
		t.Fatal("expected update to succeed")
	}
	rules := am.GetRules()
	if rules[0].Name != "updated" {
		t.Fatalf("expected 'updated', got '%s'", rules[0].Name)
	}
}

func TestAlertManager_UpdateRule_NotFound(t *testing.T) {
	am := newTestAlertManager()
	if am.UpdateRule(models.AlertRule{ID: "nonexistent"}) {
		t.Fatal("expected update to fail for unknown ID")
	}
}

func TestAlertManager_DeleteRule(t *testing.T) {
	am := newTestAlertManager()
	rule := am.AddRule(models.AlertRule{Name: "to-delete", Enabled: true})
	if !am.DeleteRule(rule.ID) {
		t.Fatal("expected delete to succeed")
	}
	if len(am.GetRules()) != 0 {
		t.Fatal("expected 0 rules after delete")
	}
}

func TestAlertManager_DeleteRule_NotFound(t *testing.T) {
	am := newTestAlertManager()
	if am.DeleteRule("nonexistent") {
		t.Fatal("expected delete to fail for unknown ID")
	}
}

func TestAlertManager_SetRules(t *testing.T) {
	am := newTestAlertManager()
	am.SetRules([]models.AlertRule{
		{ID: "1", Name: "a", Enabled: true},
		{ID: "2", Name: "b", Enabled: true},
	})
	if len(am.GetRules()) != 2 {
		t.Fatal("expected 2 rules")
	}
}

func TestAlertManager_CheckMessage_PatternMatch(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "errors", Enabled: true, Pattern: "error", MinSeverity: -1})

	events := am.CheckMessage(makeMsg(models.SevError, "host1", "app1", "an error occurred"))
	if len(events) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(events))
	}
	if events[0].RuleName != "errors" {
		t.Fatalf("expected rule name 'errors', got '%s'", events[0].RuleName)
	}
}

func TestAlertManager_CheckMessage_PatternNoMatch(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "errors", Enabled: true, Pattern: "error", MinSeverity: -1})

	events := am.CheckMessage(makeMsg(models.SevInformational, "host1", "app1", "all good"))
	if len(events) != 0 {
		t.Fatalf("expected 0 alerts, got %d", len(events))
	}
}

func TestAlertManager_CheckMessage_RegexMatch(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "regex", Enabled: true, Pattern: "err(or|eur)", UseRegex: true, MinSeverity: -1})

	events := am.CheckMessage(makeMsg(models.SevError, "host1", "app1", "une erreur"))
	if len(events) != 1 {
		t.Fatal("expected regex match")
	}
}

func TestAlertManager_CheckMessage_SeverityFilter(t *testing.T) {
	am := newTestAlertManager()
	// Alert only for Warning (4) and above (0-4)
	am.AddRule(models.AlertRule{Name: "severe", Enabled: true, MinSeverity: 4})

	// Warning (4) — should match
	events := am.CheckMessage(makeMsg(models.SevWarning, "host1", "app1", "something"))
	if len(events) != 1 {
		t.Fatal("expected alert for Warning")
	}

	// Info (6) — should NOT match (6 > 4)
	events = am.CheckMessage(makeMsg(models.SevInformational, "host1", "app1", "something"))
	if len(events) != 0 {
		t.Fatal("expected no alert for Info")
	}

	// Emergency (0) — should match
	events = am.CheckMessage(makeMsg(models.SevEmergency, "host1", "app1", "something"))
	if len(events) != 1 {
		t.Fatal("expected alert for Emergency")
	}
}

func TestAlertManager_CheckMessage_HostnameFilter(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "host", Enabled: true, Hostname: "web", MinSeverity: -1})

	events := am.CheckMessage(makeMsg(models.SevInformational, "web-server-01", "app", "msg"))
	if len(events) != 1 {
		t.Fatal("expected match for hostname containing 'web'")
	}

	events = am.CheckMessage(makeMsg(models.SevInformational, "db-server-01", "app", "msg"))
	if len(events) != 0 {
		t.Fatal("expected no match for hostname 'db-server-01'")
	}
}

func TestAlertManager_CheckMessage_AppNameFilter(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "app", Enabled: true, AppName: "nginx", MinSeverity: -1})

	events := am.CheckMessage(makeMsg(models.SevInformational, "host", "nginx", "msg"))
	if len(events) == 0 {
		t.Fatal("expected match for appName 'nginx'")
	}

	events = am.CheckMessage(makeMsg(models.SevInformational, "host", "postgres", "msg"))
	if len(events) != 0 {
		t.Fatal("expected no match for appName 'postgres'")
	}
}

func TestAlertManager_CheckMessage_DisabledRule(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "disabled", Enabled: false, Pattern: "error", MinSeverity: -1})

	events := am.CheckMessage(makeMsg(models.SevError, "host", "app", "an error"))
	if len(events) != 0 {
		t.Fatal("disabled rule should not trigger")
	}
}

func TestAlertManager_CheckMessage_Cooldown(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "cd", Enabled: true, Pattern: "error", MinSeverity: -1, Cooldown: 60})

	// First should trigger
	events := am.CheckMessage(makeMsg(models.SevError, "host", "app", "error 1"))
	if len(events) != 1 {
		t.Fatal("first message should trigger")
	}

	// Second within cooldown should NOT trigger
	events = am.CheckMessage(makeMsg(models.SevError, "host", "app", "error 2"))
	if len(events) != 0 {
		t.Fatal("second message within cooldown should not trigger")
	}
}

func TestAlertManager_CheckMessage_NoCooldown(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "nocd", Enabled: true, Pattern: "error", MinSeverity: -1, Cooldown: 0})

	am.CheckMessage(makeMsg(models.SevError, "host", "app", "error 1"))
	events := am.CheckMessage(makeMsg(models.SevError, "host", "app", "error 2"))
	if len(events) != 1 {
		t.Fatal("with cooldown=0, every match should trigger")
	}
}

func TestAlertManager_HistoryCap(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "flood", Enabled: true, MinSeverity: -1, Cooldown: 0})

	for i := 0; i < 600; i++ {
		am.CheckMessage(makeMsg(models.SevError, "host", "app", "msg"))
	}

	history := am.GetHistory()
	if len(history) > 500 {
		t.Fatalf("history should be capped at 500, got %d", len(history))
	}
}

func TestAlertManager_ClearHistory(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "test", Enabled: true, MinSeverity: -1, Cooldown: 0})
	am.CheckMessage(makeMsg(models.SevError, "host", "app", "error"))

	if len(am.GetHistory()) == 0 {
		t.Fatal("expected non-empty history")
	}
	am.ClearHistory()
	if len(am.GetHistory()) != 0 {
		t.Fatal("expected empty history after clear")
	}
}

func TestAlertManager_MultipleRules(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "r1", Enabled: true, Pattern: "error", MinSeverity: -1, Cooldown: 0})
	am.AddRule(models.AlertRule{Name: "r2", Enabled: true, Pattern: "error", MinSeverity: -1, Cooldown: 0})

	events := am.CheckMessage(makeMsg(models.SevError, "host", "app", "an error"))
	if len(events) != 2 {
		t.Fatalf("expected 2 alerts from 2 rules, got %d", len(events))
	}
}

func TestAlertManager_InvalidRegex(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "bad", Enabled: true, Pattern: "[invalid", UseRegex: true, MinSeverity: -1})

	events := am.CheckMessage(makeMsg(models.SevError, "host", "app", "test"))
	if len(events) != 0 {
		t.Fatal("invalid regex should not match")
	}
}

func TestAlertManager_CaseInsensitiveMatch(t *testing.T) {
	am := newTestAlertManager()
	am.AddRule(models.AlertRule{Name: "case", Enabled: true, Pattern: "ERROR", MinSeverity: -1})

	events := am.CheckMessage(makeMsg(models.SevError, "host", "app", "an error occurred"))
	if len(events) != 1 {
		t.Fatal("case-insensitive match should work")
	}
}
