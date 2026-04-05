package main

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// AlertRule defines a condition that triggers an alert.
type AlertRule struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Enabled     bool   `json:"enabled"`
	Pattern     string `json:"pattern"`     // Text or regex pattern to match in message
	UseRegex    bool   `json:"useRegex"`    // If true, Pattern is a regex
	MinSeverity int    `json:"minSeverity"` // -1 = any, 0 = Emergency .. 7 = Debug (alert if severity <= this)
	Hostname    string `json:"hostname"`    // Substring match on hostname (empty = any)
	AppName     string `json:"appName"`     // Substring match on appName (empty = any)
	Cooldown    int    `json:"cooldown"`    // Seconds between repeated alerts for this rule (0 = no cooldown)
}

// AlertEvent records a triggered alert.
type AlertEvent struct {
	ID        string    `json:"id"`
	RuleID    string    `json:"ruleId"`
	RuleName  string    `json:"ruleName"`
	Message   string    `json:"message"`
	Severity  string    `json:"severity"`
	Hostname  string    `json:"hostname"`
	Timestamp time.Time `json:"timestamp"`
}

// AlertManager evaluates incoming messages against alert rules.
type AlertManager struct {
	mu       sync.RWMutex
	rules    []AlertRule
	history  []AlertEvent
	lastFire map[string]time.Time // ruleID -> last fire time
	emitter  EventEmitter
}

// NewAlertManager creates an AlertManager.
func NewAlertManager(emitter EventEmitter) *AlertManager {
	return &AlertManager{
		lastFire: make(map[string]time.Time),
		emitter:  emitter,
	}
}

// SetRules replaces the entire rule set.
func (am *AlertManager) SetRules(rules []AlertRule) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.rules = rules
}

// GetRules returns the current rule set.
func (am *AlertManager) GetRules() []AlertRule {
	am.mu.RLock()
	defer am.mu.RUnlock()
	out := make([]AlertRule, len(am.rules))
	copy(out, am.rules)
	return out
}

// AddRule adds a new alert rule and returns it with a generated ID.
func (am *AlertManager) AddRule(rule AlertRule) AlertRule {
	am.mu.Lock()
	defer am.mu.Unlock()
	rule.ID = uuid.New().String()
	am.rules = append(am.rules, rule)
	return rule
}

// UpdateRule updates an existing rule by ID.
func (am *AlertManager) UpdateRule(rule AlertRule) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	for i, r := range am.rules {
		if r.ID == rule.ID {
			am.rules[i] = rule
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
			return true
		}
	}
	return false
}

// GetHistory returns recent alert events.
func (am *AlertManager) GetHistory() []AlertEvent {
	am.mu.RLock()
	defer am.mu.RUnlock()
	out := make([]AlertEvent, len(am.history))
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
func (am *AlertManager) CheckMessage(msg SyslogMessage) []AlertEvent {
	am.mu.Lock()
	defer am.mu.Unlock()

	var events []AlertEvent
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

		event := AlertEvent{
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

func (am *AlertManager) matchesRule(msg SyslogMessage, rule AlertRule) bool {
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
			re, err := safeCompileRegex(rule.Pattern)
			if err != nil {
				slog.Debug("invalid alert regex", "rule", rule.Name, "pattern", rule.Pattern, "error", err)
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
