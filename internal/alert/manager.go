package alert

import (
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"SyslogStudio/internal/event"
	"SyslogStudio/internal/models"
)

// AlertManager evaluates incoming messages against alert rules.
type AlertManager struct {
	mu       sync.RWMutex
	rules    []models.AlertRule
	compiled map[string]*regexp.Regexp // ruleID -> compiled regex (regex rules only)
	history  []models.AlertEvent
	lastFire map[string]time.Time // ruleID -> last fire time
	emitter  event.EventEmitter
}

// NewAlertManager creates an AlertManager.
func NewAlertManager(emitter event.EventEmitter) *AlertManager {
	return &AlertManager{
		compiled: make(map[string]*regexp.Regexp),
		lastFire: make(map[string]time.Time),
		emitter:  emitter,
	}
}

// rebuildCompiled recompiles the regex cache from the current rules. Must be
// called under am.mu (write). Compiling once here — rather than per message in
// matchesRule — keeps the hot path off the regex compiler.
func (am *AlertManager) rebuildCompiled() {
	compiled := make(map[string]*regexp.Regexp, len(am.rules))
	for _, r := range am.rules {
		if r.UseRegex && r.Pattern != "" {
			re, err := models.SafeCompileRegex(r.Pattern)
			if err != nil {
				slog.Debug("invalid alert regex", "rule", r.Name, "pattern", r.Pattern, "error", err)
				continue
			}
			compiled[r.ID] = re
		}
	}
	am.compiled = compiled
}

// SetRules replaces the entire rule set.
func (am *AlertManager) SetRules(rules []models.AlertRule) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.rules = rules
	am.rebuildCompiled()
}

// GetRules returns the current rule set.
func (am *AlertManager) GetRules() []models.AlertRule {
	am.mu.RLock()
	defer am.mu.RUnlock()
	out := make([]models.AlertRule, len(am.rules))
	copy(out, am.rules)
	return out
}

// AddRule adds a new alert rule and returns it with a generated ID.
func (am *AlertManager) AddRule(rule models.AlertRule) models.AlertRule {
	am.mu.Lock()
	defer am.mu.Unlock()
	rule.ID = uuid.New().String()
	am.rules = append(am.rules, rule)
	am.rebuildCompiled()
	return rule
}

// UpdateRule updates an existing rule by ID.
func (am *AlertManager) UpdateRule(rule models.AlertRule) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	for i, r := range am.rules {
		if r.ID == rule.ID {
			am.rules[i] = rule
			am.rebuildCompiled()
			return true
		}
	}
	return false
}

// DeleteRule removes a rule by ID.
func (am *AlertManager) DeleteRule(id string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	for i, r := range am.rules {
		if r.ID == id {
			am.rules = append(am.rules[:i], am.rules[i+1:]...)
			delete(am.lastFire, id)
			am.rebuildCompiled()
			return true
		}
	}
	return false
}

// GetHistory returns recent alert events.
func (am *AlertManager) GetHistory() []models.AlertEvent {
	am.mu.RLock()
	defer am.mu.RUnlock()
	out := make([]models.AlertEvent, len(am.history))
	copy(out, am.history)
	return out
}

// ClearHistory removes all alert history.
func (am *AlertManager) ClearHistory() {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.history = nil
}

// CheckMessage evaluates a message against all enabled rules.
// Returns triggered events (may be empty).
func (am *AlertManager) CheckMessage(msg models.SyslogMessage) []models.AlertEvent {
	am.mu.Lock()
	defer am.mu.Unlock()

	var events []models.AlertEvent
	now := time.Now()

	for _, rule := range am.rules {
		if !rule.Enabled {
			continue
		}

		if !am.matchesRule(msg, rule) {
			continue
		}

		// Cooldown check
		if rule.Cooldown > 0 {
			if last, ok := am.lastFire[rule.ID]; ok {
				if now.Sub(last) < time.Duration(rule.Cooldown)*time.Second {
					continue
				}
			}
		}

		event := models.AlertEvent{
			ID:        uuid.New().String(),
			RuleID:    rule.ID,
			RuleName:  rule.Name,
			Message:   msg.Message,
			Severity:  msg.SeverityLabel,
			Hostname:  msg.Hostname,
			Timestamp: now,
		}

		events = append(events, event)
		am.history = append(am.history, event)
		am.lastFire[rule.ID] = now

		// Cap history at 500
		if len(am.history) > 500 {
			am.history = am.history[len(am.history)-500:]
		}
	}

	return events
}

func (am *AlertManager) matchesRule(msg models.SyslogMessage, rule models.AlertRule) bool {
	// Severity check: alert if message severity <= minSeverity (lower = more severe)
	if rule.MinSeverity >= 0 && int(msg.Severity) > rule.MinSeverity {
		return false
	}

	// Hostname filter
	if rule.Hostname != "" {
		if !strings.Contains(strings.ToLower(msg.Hostname), strings.ToLower(rule.Hostname)) {
			return false
		}
	}

	// AppName filter
	if rule.AppName != "" {
		if !strings.Contains(strings.ToLower(msg.AppName), strings.ToLower(rule.AppName)) {
			return false
		}
	}

	// Pattern match
	if rule.Pattern != "" {
		if rule.UseRegex {
			re := am.compiled[rule.ID]
			if re == nil {
				// Not in the cache (invalid pattern, logged at build time).
				return false
			}
			if !re.MatchString(msg.Message) && !re.MatchString(msg.RawMessage) {
				return false
			}
		} else {
			p := strings.ToLower(rule.Pattern)
			if !strings.Contains(strings.ToLower(msg.Message), p) &&
				!strings.Contains(strings.ToLower(msg.RawMessage), p) {
				return false
			}
		}
	}

	return true
}
